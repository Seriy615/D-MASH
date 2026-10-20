// Bounded synthetic test transport, NOT a production IPC endpoint. Production
// actor dispatches the C++ API directly and never accepts a DB path or SQL.
#include "inbox_sql_store.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <cmath>
#include <iostream>
#include <stdexcept>
using dmash::InboxSqlStore;
using dmash::EncryptedRow;
static void require(bool v){if(!v)throw std::runtime_error("Invalid Inbox test request");}
static std::optional<qint64> revision(const QJsonValue& v){
    if(v.isNull())return std::nullopt;
    const auto n=v.toDouble(-1);require(v.isDouble()&&std::isfinite(n)&&std::floor(n)==n&&n>=1&&n<=9007199254740991.0);return qint64(n);
}
static QByteArray decode(const QJsonValue& value,int max){
    require(value.isString()&&value.toString().size()<=max*2);
    const auto input=value.toString().toLatin1();const auto result=QByteArray::fromBase64Encoding(input,QByteArray::AbortOnBase64DecodingErrors);
    require(bool(result)&&result.decoded.size()<=max&&result.decoded.toBase64()==input);return result.decoded;
}
static std::optional<EncryptedRow> row(const QJsonValue& value){
    if(value.isNull())return std::nullopt;require(value.isObject());const auto o=value.toObject();require(o.size()==2&&o.contains("iv")&&o.contains("ciphertext"));
    return EncryptedRow{QString(),0,decode(o["iv"],12),decode(o["ciphertext"],65536)};
}
static QJsonValue encode(const std::optional<EncryptedRow>& r){
    if(!r)return QJsonValue::Null;return QJsonObject{{"key",r->key},{"revision",double(r->revision)},{"iv",QString::fromLatin1(r->iv.toBase64())},{"ciphertext",QString::fromLatin1(r->ciphertext.toBase64())}};
}
int main(int argc,char** argv){
    QCoreApplication app(argc,argv);
    try{
        require(argc==2||argc==4);InboxSqlStore store(QString::fromLocal8Bit(argv[1]),argc==4?QString(argv[2]).toInt():4096,argc==4?QString(argv[3]).toLongLong():32*1024*1024);
        QFile input;require(input.open(stdin,QIODevice::ReadOnly));
        while(!input.atEnd()){
            auto line=input.readLine(128*1024+1);if(line.isEmpty())break;QJsonObject reply;
            try{
                require(line.size()<=128*1024&&line.endsWith('\n'));
                QJsonParseError error;const auto doc=QJsonDocument::fromJson(line,&error);require(error.error==QJsonParseError::NoError&&doc.isObject());const auto q=doc.object();const auto op=q["op"].toString();QJsonValue result;
                if(op=="read")result=encode(store.read(q["key"].toString()));
                else if(op=="all"||op=="allBindings") {QJsonArray rows;for(const auto& r:op=="all"?store.all():store.allBindings())rows.append(encode(r));result=rows;}
                else if(op=="reconcile"){store.reconcile();result=true;}
                else if(op=="cas")result=store.cas(q["key"].toString(),revision(q["revision"]),row(q["row"]));
                else if(op=="promote"){const auto source=revision(q["sourceRevision"]);require(bool(source));result=store.promote(q["sourceKey"].toString(),*source,q["targetKey"].toString(),revision(q["targetRevision"]),row(q["row"]));}
                else if(op=="close"){store.close();result=true;}
                else require(false);
                reply={{"ok",true},{"value",result}};
            }catch(const std::exception& e){reply={{"ok",false},{"error",QString::fromLatin1(e.what())}};}
            std::cout<<QJsonDocument(reply).toJson(QJsonDocument::Compact).constData()<<'\n'<<std::flush;
            if(!line.endsWith('\n'))break;
        }
        return 0;
    }catch(...){std::cerr<<"Inbox test bridge unavailable\n";return 1;}
}
