#include "inbox_sql_store.h"
#include <QCoreApplication>
#include <QProcess>
#include <QSqlQuery>
#include <QTemporaryDir>
#include <QUuid>
#include <QVariant>
#include <future>
#include <iostream>
#include <stdexcept>
using dmash::InboxSqlStore;
using dmash::EncryptedRow;
static void require(bool value) { if (!value) throw std::runtime_error("Inbox test assertion failed"); }
template<class F> static void rejects(F f) {
    bool failed = false; try { f(); } catch (const std::exception&) { failed = true; } require(failed);
}
static const QString a(64, 'a'), b(64, 'b'), c(64, 'c');
static EncryptedRow blob(int n = 32, char ch = 'c') { return {QString(), 0, QByteArray(12, 'i'), QByteArray(n, ch)}; }
class Inspect {
  public:
    QSqlDatabase db; QString name = QUuid::createUuid().toString();
    explicit Inspect(const QString& file) { db=QSqlDatabase::addDatabase("QSQLITE",name);db.setDatabaseName(file);require(db.open()); }
    ~Inspect() { db.close();db=QSqlDatabase();QSqlDatabase::removeDatabase(name); }
    void exec(const QString& s) { QSqlQuery q(db);require(q.exec(s)); }
    qint64 scalar(const QString& s) { QSqlQuery q(db);require(q.exec(s)&&q.next());return q.value(0).toLongLong(); }
    void totals(int count, int bytes) {
        require(scalar("SELECT count FROM node_inbox_usage WHERE bucket='records'")==count);
        require(scalar("SELECT bytes FROM node_inbox_usage WHERE bucket='records'")==bytes);
    }
};
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        const auto args=app.arguments();
        if(args.size()==4 && args[1]=="--crash") {
            InboxSqlStore store(args[2]);
            if(args[3]=="mid") store.setTestHook([](const char* point){if(QString(point)=="promote_after_target") std::_Exit(73);});
            require(store.promote(a,1,b,std::nullopt,blob(40,'p')));
            std::_Exit(74); // actual committed call, without destructor/close
        }
        QTemporaryDir dir;require(dir.isValid());const auto file=dir.filePath("node.sqlite");
        {
            InboxSqlStore one(file,2,1024),two(file,2,1024);one.reconcile();
            require(one.cas("owner",std::nullopt,blob()));
            require(one.all().isEmpty()&&one.allBindings().size()==1);
            require(one.cas(a,std::nullopt,blob()));require(!two.cas(a,std::nullopt,blob()));
            require(two.cas(b,std::nullopt,blob()));rejects([&]{one.cas(c,std::nullopt,blob());});
            require(!one.read(c));Inspect inspect(file);inspect.totals(2,320);
            require(!two.promote(a,2,b,1,blob()));require(!two.promote(a,1,b,2,blob()));
            rejects([&]{two.promote(a,1,a,1,blob());});rejects([&]{two.promote(a,1,"owner",1,blob());});
            require(one.promote(a,1,b,1,std::nullopt)); // preserve pending/seen ciphertext+revision
            require(!two.read(a)&&two.read(b)->revision==1&&two.read(b)->ciphertext==blob().ciphertext);
            inspect.totals(1,160);require(!two.cas(a,1,blob()));
            require(two.cas(a,std::nullopt,blob()));require(one.promote(a,1,c,std::nullopt,blob(64)));
            require(!two.read(a)&&two.read(c)->revision==1);inspect.totals(2,352);
            require(two.cas(c,1,std::nullopt));require(!two.cas(c,1,blob()));require(!two.cas(c,std::nullopt,std::nullopt));
            require(one.cas(a,std::nullopt,blob()));inspect.exec("CREATE TRIGGER fail_promote BEFORE DELETE ON node_inbox_rows WHEN OLD.key='"+a+"' BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END");
            rejects([&]{one.promote(a,1,c,std::nullopt,blob());});require(one.read(a)&&!one.read(c));inspect.totals(2,320);
            inspect.exec("DROP TRIGGER fail_promote");
            inspect.exec("CREATE TRIGGER fail_usage BEFORE UPDATE ON node_inbox_usage WHEN NEW.bucket='records' BEGIN SELECT RAISE(ABORT,'synthetic metadata failure'); END");
            rejects([&]{one.cas(a,1,blob(40));});require(one.read(a)->revision==1);inspect.totals(2,320);
            inspect.exec("DROP TRIGGER fail_usage");
            rejects([&]{one.cas(c,std::nullopt,blob(65537));});rejects([&]{one.cas(c,0,blob());});
            rejects([&]{one.cas(c,9007199254740991LL,blob());});
            require(std::async(std::launch::async,[&]{try{one.read(a);return false;}catch(...){return true;}}).get());
            one.close();rejects([&]{one.cas(c,std::nullopt,blob());});
        }
        {
            InboxSqlStore reopened(file,1,1024);require(reopened.all().size()==2);
            require(reopened.cas(b,1,blob(16))); // lower configured count permits non-growth
            rejects([&]{reopened.cas(c,std::nullopt,blob());});
            require(reopened.cas(a,1,std::nullopt));require(reopened.all().size()==1);
            Inspect inspect(file);inspect.totals(1,144);
            inspect.exec("UPDATE node_inbox_usage SET bytes=0 WHERE bucket='records'");
            rejects([&]{reopened.cas(b,2,blob());});require(reopened.read(b)->revision==2);
            reopened.reconcile();inspect.totals(1,144);
        }
        {
            InboxSqlStore orphan(dir.filePath("orphan.sqlite"));require(orphan.cas(a,std::nullopt,blob()));
            rejects([&]{orphan.cas("owner",std::nullopt,blob());});require(!orphan.read("owner"));
        }
        {
            InboxSqlStore bindings(dir.filePath("bindings.sqlite"));require(bindings.cas("owner",std::nullopt,blob()));
            for(int i=0;i<32;i++)require(bindings.cas("binding:"+QString::number(i,16).rightJustified(64,'0'),std::nullopt,blob()));
            rejects([&]{bindings.cas("binding:"+c,std::nullopt,blob());});
            require(bindings.all().isEmpty()&&bindings.allBindings().size()==33);
        }
        {
            InboxSqlStore bindings(dir.filePath("binding-bytes.sqlite"));require(bindings.cas("owner",std::nullopt,blob()));
            for(int i=0;i<3;i++)require(bindings.cas("binding:"+QString::number(i,16).rightJustified(64,'0'),std::nullopt,blob(65536)));
            rejects([&]{bindings.cas("binding:"+c,std::nullopt,blob(65536));});require(bindings.allBindings().size()==4);
        }
        {
            InboxSqlStore bytes(dir.filePath("bytes.sqlite"),5,1024);
            require(bytes.cas(a,std::nullopt,blob(896)));rejects([&]{bytes.cas(b,std::nullopt,blob(16));});
            require(bytes.cas(a,1,blob(16)));require(bytes.cas(b,std::nullopt,blob(16)));
            rejects([&]{bytes.cas(c,std::nullopt,blob(700));});
            require(!bytes.read(c));
            rejects([&]{bytes.promote(a,2,c,std::nullopt,blob(900));});
            require(bytes.read(a)&&!bytes.read(c));
        }
        {
            const auto corrupt=dir.filePath("corrupt.sqlite");InboxSqlStore store(corrupt);Inspect inspect(corrupt);
            inspect.exec("PRAGMA ignore_check_constraints=ON");
            inspect.exec("INSERT INTO node_inbox_rows VALUES('"+a+"','records',1,zeroblob(12),zeroblob(1048576))");
            rejects([&]{store.read(a);});rejects([&]{store.all();});rejects([&]{store.reconcile();});
            inspect.exec("DELETE FROM node_inbox_rows");store.reconcile();
            inspect.exec("UPDATE node_inbox_meta SET version=2");
            rejects([&]{InboxSqlStore unknown(corrupt);});require(inspect.scalar("SELECT version FROM node_inbox_meta")==2);
            rejects([&]{InboxSqlStore invalid(dir.filePath("invalid.sqlite"),0,1024);});
        }
        {
            const auto concurrent=dir.filePath("concurrent.sqlite");
            {InboxSqlStore seed(concurrent);require(seed.cas(a,std::nullopt,blob()));}
            std::promise<void> go,readyOne,readyTwo;auto gate=go.get_future().share();
            auto worker=[&](std::promise<void>& ready){InboxSqlStore connection(concurrent);ready.set_value();gate.wait();return connection.cas(a,1,blob(40));};
            auto one=std::async(std::launch::async,worker,std::ref(readyOne));
            auto two=std::async(std::launch::async,worker,std::ref(readyTwo));
            readyOne.get_future().get();readyTwo.get_future().get();go.set_value();
            const bool first=one.get(),second=two.get();require(first!=second);
            InboxSqlStore restored(concurrent);require(restored.read(a)->revision==2);Inspect inspect(concurrent);inspect.totals(1,168);
        }
        std::cout<<"PASS native Inbox atomic CAS/promote/usage/quota/rollback/reopen/owner/lifetime\n";
        // Crash in the actual promote transaction after target write but before
        // source deletion/usage commit, then after actual durable commit.
        for(const auto& mode:{QString("mid"),QString("committed")}) {
            const auto crashFile=dir.filePath(mode+".sqlite");{InboxSqlStore seed(crashFile);require(seed.cas(a,std::nullopt,blob()));}
            QProcess child;child.start(app.applicationFilePath(),{"--crash",crashFile,mode});require(child.waitForFinished(10000));
            require(child.exitCode()==(mode=="mid"?73:74));
            InboxSqlStore restored(crashFile);Inspect inspect(crashFile);
            if(mode=="mid"){require(restored.read(a)&&!restored.read(b));inspect.totals(1,160);}
            else {require(!restored.read(a)&&restored.read(b));inspect.totals(1,168);}
            restored.reconcile();
        }
        std::cout<<"PASS actual process exit during promote rolls back all rows/usage; committed exit retains all\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
