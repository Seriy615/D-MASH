#include "nonce_hash.h"
#include "crypto_port.h"
#include <QCoreApplication>
#include <stdexcept>
int main(int argc,char**argv){QCoreApplication app(argc,argv);
 for(int length:{0,55,56,63,64,65,119,120,127,128}){
  QByteArray prefix(length,'x');dmash::NonceHash h(prefix);
  for(quint64 n:{quint64(0),quint64(9007199254740991ULL),quint64(0xffffffffffffffffULL)}){
   QByteArray suffix(8,Qt::Uninitialized);for(int i=0;i<8;++i)suffix[7-i]=char(n>>(8*i));
   if(h.digest(n)!=dmash::CryptoPort::sha256(prefix+suffix))throw std::runtime_error("u64 parity");
  }
 }
 dmash::NonceHash batch("bounded nonce search");
 const auto first=batch.search(0,4096,8);if(!first)throw std::runtime_error("missing expected target");
 for(quint64 nonce=0;nonce<=first->nonce;++nonce){const auto digest=batch.digest(nonce);const bool meets=static_cast<unsigned char>(digest[0])==0;if(meets!=(nonce==first->nonce))throw std::runtime_error("search skipped first target");}
 if(first->digest!=batch.digest(first->nonce))throw std::runtime_error("search digest mismatch");
 const auto edge=batch.search(0xffffffffffffffffULL,1,0);if(!edge||edge->nonce!=0xffffffffffffffffULL)throw std::runtime_error("search u64 edge");
 std::atomic_bool cancelled{true};bool stopped=false;try{batch.search(0,4096,256,&cancelled);}catch(const std::exception&){stopped=true;}if(!stopped)throw std::runtime_error("search cancellation ignored");
 bool bounded=false;try{batch.search(0xffffffffffffffffULL,2,8);}catch(const std::exception&){bounded=true;}if(!bounded)throw std::runtime_error("search overflow accepted");

}
