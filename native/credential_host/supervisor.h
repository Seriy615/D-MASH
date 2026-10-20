#pragma once
#include "broker_service.h"
#include "node_supervisor.h"
#include <QLocalSocket>
#include <QProcess>
#ifdef Q_OS_WIN
#include "os_windows.h"
#endif
namespace dmash::credential {
class Supervisor final : public NodeSupervisor {
  public:
    Supervisor(QString binary, QString profile);
    ~Supervisor();
    QJsonObject start(const broker::BrokerResult& session) override;
    bool provePreviousStopped(const broker::ControlState&, broker::RootCodec::Current) override;
    QJsonObject takeStoppedFloors() override;
    QJsonArray renewCapabilities() override;
    bool running() const override;
    void stop() override;

  private:
    QString binary_, profile_;
    QJsonObject stoppedFloors_;
    bool leaseRenewalSupported_ = false;
    void writeChildReceipt(const broker::BrokerResult&);
    std::unique_ptr<QLocalSocket> lease_;
#ifndef Q_OS_WIN
    std::unique_ptr<QProcess> child_;
#else
    std::unique_ptr<dmash::windowsLocal::ChildProcess> child_;
#endif
};
} // namespace dmash::credential
