#pragma once
#include "root_codec.h"
namespace dmash::credential {
// Runs in the credential broker worker, outside the network daemon.
// Exact existing BLAKE3 JavaScript, native Ed25519 public derivation.
QByteArray verifyOrMineNodeSeed(const QByteArray& existing, broker::RootCodec::Current current);
QString nodePublicId(const QByteArray& seed);
} // namespace dmash::credential
