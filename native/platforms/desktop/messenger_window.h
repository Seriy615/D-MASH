#pragma once
#include "session_client.h"
#include "account_controller.h"
#include "message_history.h"
#include <QMainWindow>
class QLabel;class QPushButton;class QListWidget;class QTextEdit;class QLineEdit;
class MessengerWindow final : public QMainWindow {
 Q_OBJECT
public:
 explicit MessengerWindow(QWidget* parent=nullptr);
 SessionClient* session(){return &session_;}
 void openAccountProfile(const QString&);
 void importAccountProfile(const QJsonObject&);
private:
 void loginDialog();void createProfileDialog();void createAccountDialog();bool rootUnlockDialog(const QJsonObject& profile = {});void nodeSettings();void requestNodeStart(const QJsonArray&,bool);void updateNodeStatus(const QJsonObject&);void showHistory(const QJsonArray&);void updateControls();
 SessionClient session_;
 std::unique_ptr<AccountController> accountOwner_;
 QJsonArray accounts_;QJsonObject hostStatus_;QJsonArray pendingEndpoints_;bool pendingDirect_=false,startNodeAfterUnlock_=false;
 QString peer_;bool loggedIn_=false,working_=false,needRoot_=false;
 QLabel *status_,*account_,*chatTitle_,*notice_;
 QPushButton *nodeToggle_,*nodeSettings_,*refresh_,*detach_,*login_,*logout_,*import_,*create_,*send_,*cancel_;
 bool createAfterUnlock_=false;
 QListWidget* chats_;MessageHistory* history_;QTextEdit* compose_;
};
