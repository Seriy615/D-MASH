#include "credential_host.h"
#include "supervisor.h"
#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>
#include <QTimer>
#include <csignal>
#include <cstdio>
namespace {
volatile std::sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
} // namespace
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    QCommandLineParser cli;
    cli.addHelpOption();
    cli.addOption({"profile", "Private credential/Account owner directory", "directory"});
    cli.addOption(
        {"node-host", "Separate transport daemon executable (optional for Saved)", "binary"});
    cli.process(app);
    try {
        if (!cli.isSet("profile"))
            throw std::runtime_error("PROFILE_REQUIRED");
        std::shared_ptr<dmash::credential::NodeSupervisor> node;
        if (cli.isSet("node-host") && QFileInfo(cli.value("node-host")).isExecutable())
            node = std::make_shared<dmash::credential::Supervisor>(
                cli.value("node-host"), QDir(cli.value("profile")).filePath("node"));
        dmash::credential::CredentialHost host(cli.value("profile"), node);
        std::signal(SIGINT, stop);
        std::signal(SIGTERM, stop);
        QTimer timer;
        QObject::connect(&timer, &QTimer::timeout, &app, [&] {
            if (stopping)
                app.quit();
        });
        timer.start(50);
        return app.exec();
    } catch (const std::exception& e) {
        fprintf(stderr, "Credential host: %s\n", e.what());
        return 1;
    }
}
