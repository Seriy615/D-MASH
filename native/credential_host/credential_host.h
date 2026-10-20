#pragma once
#include "node_supervisor.h"
#include <QCoreApplication>
#include <memory>
namespace dmash::credential {
// Own this object in a Qt event-loop process; UI clients have a separate lifetime.
class CredentialHost final {
  public:
    CredentialHost(QString profile, std::shared_ptr<NodeSupervisor> supervisor);
    ~CredentialHost();
    QString endpoint() const;

  private:
    struct State;
    std::unique_ptr<State> state_;
};
} // namespace dmash::credential
