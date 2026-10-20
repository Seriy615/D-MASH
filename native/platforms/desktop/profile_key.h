#pragma once
#include <QByteArray>
#include <QString>
// Development app-local key, not a hardware/vault key. Never passed to Node.
QByteArray openAppLocalKey(const QString& profileDirectory,const QString& accountDatabasePath);
