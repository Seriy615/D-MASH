#include "nonce_hash.h"
#include <stdexcept>
#include <limits>
namespace dmash {
NonceHash::NonceHash(const QByteArray& prefix) {
    if (prefix.size()>65536) throw std::runtime_error("nonce prefix limit");
    prefix_=EVP_MD_CTX_new(); work_=EVP_MD_CTX_new();
    if(!prefix_||!work_||EVP_DigestInit_ex(prefix_,EVP_sha256(),nullptr)!=1||
       EVP_DigestUpdate(prefix_,prefix.constData(),size_t(prefix.size()))!=1) {
        EVP_MD_CTX_free(prefix_);EVP_MD_CTX_free(work_);
        throw std::runtime_error("nonce hash initialization");
    }
}
NonceHash::~NonceHash(){EVP_MD_CTX_free(prefix_);EVP_MD_CTX_free(work_);}
QByteArray NonceHash::digest(quint64 nonce) {
    unsigned char be[8];for(int i=0;i<8;++i)be[7-i]=static_cast<unsigned char>(nonce>>(8*i));
    QByteArray out(32,Qt::Uninitialized);unsigned n=0;
    if(EVP_MD_CTX_copy_ex(work_,prefix_)!=1||EVP_DigestUpdate(work_,be,8)!=1||
       EVP_DigestFinal_ex(work_,reinterpret_cast<unsigned char*>(out.data()),&n)!=1||n!=32)
        throw std::runtime_error("nonce hash failure");
    return out;
}
std::optional<NonceHash::Match> NonceHash::search(quint64 start, int count, int difficulty, const std::atomic_bool* cancelled) {
    if(count<1 || count>4096 || difficulty<0 || difficulty>256 || start>std::numeric_limits<quint64>::max()-quint64(count-1))
        throw std::runtime_error("nonce search bounds");
    for(int offset=0;offset<count;++offset){
        if((offset&255)==0 && cancelled && cancelled->load())throw std::runtime_error("nonce search cancelled");
        auto value=digest(start+quint64(offset));int bits=0;
        for(const auto byte:value){const auto b=static_cast<unsigned char>(byte);if(!b){bits+=8;continue;}for(unsigned mask=128;mask && !(b&mask);mask>>=1)++bits;break;}
        if(bits>=difficulty)return Match{start+quint64(offset),std::move(value)};
    }
    return std::nullopt;
}

}
