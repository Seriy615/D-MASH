#pragma once
#include <QJsonArray>
#include <QJsonObject>
#include <QString>
#include <functional>
#include <map>
#include <mutex>
namespace dmash::credential {
class DaemonRpc final {
  public:
    ~DaemonRpc();
    void install(const QJsonObject& ready);
    void clear();
    QJsonArray refreshCapabilities(const std::function<QJsonArray()>& renew);
    void closeScope(const QString& scope);
    QJsonObject call(const QString& scope, const QString& method, const QJsonObject& params,
                     bool broker = false);

  private:
    std::mutex mutex_;
    QJsonObject ready_;
    std::map<QString, qintptr> sockets_;
};
} // namespace dmash::credential
