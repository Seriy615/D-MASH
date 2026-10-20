// Reconstructed from pre-reboot tool-call source; current run is recorded separately.
#include <QCoreApplication>
#include <QFile>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QTemporaryDir>
#include <QTimer>
#include <QWebSocket>
#include <QWebSocketServer>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstdio>
#include <cstring>
extern "C" {
#include "quickjs.h"
}
static bool require(bool ok,const char* what){std::printf("%s %s\n",ok?"PASS":"FAIL",what);return ok;}
int main(int argc,char**argv){
 QCoreApplication app(argc,argv);if(argc!=3)return 2;
 JSRuntime*rt=JS_NewRuntime();JS_SetMemoryLimit(rt,128*1024*1024);JSContext*ctx=JS_NewContext(rt);
 const char*src="class S{#n=40;get(){return this.#n+new Uint8Array([2])[0]}};new S().get()";JSValue value=JS_Eval(ctx,src,strlen(src),"synthetic",JS_EVAL_TYPE_GLOBAL);int32_t n=0;bool js=JS_ToInt32(ctx,&n,value)==0&&n==42;JS_FreeValue(ctx,value);JS_FreeContext(ctx);JS_FreeRuntime(rt);
 if(!require(js,"QuickJS private field/typed native engine"))return 1;
 unsigned char bytes[32],digest[EVP_MAX_MD_SIZE];unsigned int len=0;
 if(!require(RAND_bytes(bytes,sizeof bytes)==1&&EVP_Digest("abc",3,digest,&len,EVP_sha256(),nullptr)==1&&QByteArray((char*)digest,len).toHex()=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","OpenSSL CSPRNG and SHA256 vector"))return 1;
 unsigned char key[16]={},iv[12]={},plain[16]={},cipher[32]={},tag[16]={};int out=0,last=0;auto*c=EVP_CIPHER_CTX_new();bool aes=EVP_EncryptInit_ex(c,EVP_aes_128_gcm(),nullptr,key,iv)==1&&EVP_EncryptUpdate(c,cipher,&out,plain,16)==1&&EVP_EncryptFinal_ex(c,cipher+out,&last)==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag)==1;EVP_CIPHER_CTX_free(c);
 if(!require(aes&&QByteArray((char*)cipher,16).toHex()=="0388dace60b6a392f328c2b971b2fe78"&&QByteArray((char*)tag,16).toHex()=="ab6e47d42cec13bdf53a67b21257bddf","OpenSSL AES128-GCM NIST vector"))return 1;
 QTemporaryDir temp;if(!temp.isValid())return 1;auto db=QSqlDatabase::addDatabase("QSQLITE");db.setDatabaseName(temp.filePath("synthetic.sqlite"));if(!db.open())return 1;QSqlQuery q(db);
 bool sql=q.exec("PRAGMA synchronous=FULL")&&q.exec("CREATE TABLE jobs(id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,payload BLOB NOT NULL)")&&db.transaction()&&q.exec("INSERT INTO jobs VALUES(1,1,X'010203')")&&db.commit()&&db.transaction()&&q.exec("UPDATE jobs SET revision=2 WHERE id=1 AND revision=1")&&q.numRowsAffected()==1&&db.commit()&&db.transaction()&&q.exec("UPDATE jobs SET revision=3 WHERE id=1 AND revision=1")&&q.numRowsAffected()==0&&db.rollback();db.close();sql=sql&&db.open()&&q.exec("SELECT revision FROM jobs WHERE id=1")&&q.next()&&q.value(0).toInt()==2;
 if(!require(sql,"SQLite transaction CAS/stale reject/reopen"))return 1;
 std::printf("Qt %s TLS %s backend %s\n",qVersion(),qPrintable(QSslSocket::sslLibraryVersionString()),qPrintable(QSslSocket::activeBackend()));
 if(!require(QSslSocket::supportsSsl()&&QSslSocket::activeBackend()=="openssl","Qt OpenSSL TLS backend"))return 1;
 QFile certFile(argv[1]),keyFile(argv[2]);if(!certFile.open(QIODevice::ReadOnly)||!keyFile.open(QIODevice::ReadOnly))return 1;QSslCertificate cert(certFile.readAll(),QSsl::Pem);QSslKey sslKey(keyFile.readAll(),QSsl::Rsa,QSsl::Pem);
 QWebSocketServer server("synthetic-probe",QWebSocketServer::SecureMode);auto serverCfg=QSslConfiguration::defaultConfiguration();serverCfg.setLocalCertificate(cert);serverCfg.setPrivateKey(sslKey);serverCfg.setPeerVerifyMode(QSslSocket::VerifyNone);server.setSslConfiguration(serverCfg);if(!server.listen(QHostAddress::LocalHost,0))return 1;
 QObject::connect(&server,&QWebSocketServer::newConnection,&app,[&]{auto*s=server.nextPendingConnection();QObject::connect(s,&QWebSocket::textMessageReceived,s,[s](const QString&m){s->sendTextMessage(m);});});
 QWebSocket client;auto clientCfg=QSslConfiguration::defaultConfiguration();clientCfg.addCaCertificate(cert);clientCfg.setPeerVerifyMode(QSslSocket::VerifyPeer);client.setSslConfiguration(clientCfg);
 QObject::connect(&client,&QWebSocket::sslErrors,&app,[&](const QList<QSslError>&){require(false,"WSS certificate verification");app.exit(1);});
 QObject::connect(&client,&QWebSocket::connected,&app,[&]{client.sendTextMessage("opaque synthetic");});
 QObject::connect(&client,&QWebSocket::textMessageReceived,&app,[&](const QString&m){bool ok=require(m=="opaque synthetic","WSS verified localhost TLS echo");client.close();server.close();app.exit(ok?0:1);});
 QTimer::singleShot(5000,&app,[&]{require(false,"WSS deadline");app.exit(1);});client.open(QUrl(QString("wss://localhost:%1").arg(server.serverPort())));return app.exec();
}
