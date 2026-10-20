#include "js_actor.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <stdexcept>
int main(int argc,char**argv){
 QCoreApplication app(argc,argv);QTemporaryDir dir;if(!dir.isValid())return 1;
 dmash::JsActor actor(dir.filePath("node-profile"));int events=0;actor.onEvent=[&](const QJsonObject&){++events;};
 // Deliberately invalid synthetic Node identity produces a queued report.
 // Closing before dispatch must invalidate that callback's generation.
 dmash::TransportBundle bundle;bundle.nodeSeed=QByteArray(32,0);bundle.storageKey=QByteArray(32,0);bundle.baseNcrh=QByteArray(32,0);
 actor.initialize(std::move(bundle));
 bool duplicateRejected=false;try{actor.initialize(dmash::TransportBundle{});}catch(const std::exception&){duplicateRejected=true;}
 if(!duplicateRejected)throw std::runtime_error("duplicate initialize");
 actor.close();actor.close();QCoreApplication::processEvents();
 if(events)throw std::runtime_error("late actor report");
 int rejected=0;
 try{actor.initialize(dmash::TransportBundle{});}catch(const std::exception&){++rejected;}
 try{actor.connectPeer(0);}catch(const std::exception&){++rejected;}
 try{actor.queryService(0);}catch(const std::exception&){++rejected;}
 try{actor.snapshot();}catch(const std::exception&){++rejected;}
 if(rejected!=4)throw std::runtime_error("closed actor entry");
}
