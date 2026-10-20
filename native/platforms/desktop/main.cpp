#include "messenger_window.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QStandardPaths>
int main(int argc,char** argv){QApplication app(argc,argv);app.setApplicationName("D-MASH");app.setOrganizationName("D-MASH");QCommandLineParser cli;cli.addHelpOption();cli.addOption({"session-fd","One-shot inherited private broker-to-UI handoff socket","descriptor"});cli.addOption({"account-profile","Private existing/import destination Account database","file"});cli.process(app);MessengerWindow window;window.openAccountProfile(cli.isSet("account-profile")?cli.value("account-profile"):QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)+"/account.sqlite");window.show();if(cli.isSet("session-fd")){bool ok=false;int fd=cli.value("session-fd").toInt(&ok);window.session()->attachDescriptor(ok?fd:-1);}return app.exec();}
