#include "profile_key.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRandomGenerator>
#include <QTemporaryFile>
#include <stdexcept>
#include <string>
#include <cstring>
#ifdef Q_OS_UNIX
#include <unistd.h>
#endif
#ifdef Q_OS_WIN
#include "os_windows.h"
#include <windows.h>
#endif
QByteArray openAppLocalKey(const QString& directory,const QString& accountDatabasePath){
#ifdef Q_OS_WIN
 if(!QDir(QFileInfo(directory).absolutePath()).exists()&&!QDir().mkpath(QFileInfo(directory).absolutePath()))throw std::runtime_error("PROFILE_DIRECTORY_UNAVAILABLE");
 try{dmash::windowsLocal::ensurePrivateProfile(directory.toStdWString());}
 catch(const std::exception& e){throw std::runtime_error(std::string("PROFILE_KEY_DIRECTORY:")+e.what());}
#else
 if(!QDir(directory).exists()&&!QDir().mkpath(directory))throw std::runtime_error("PROFILE_DIRECTORY_UNAVAILABLE");
 if(!QFile::setPermissions(directory,QFileDevice::ReadOwner|QFileDevice::WriteOwner|QFileDevice::ExeOwner))throw std::runtime_error("PROFILE_DIRECTORY_UNAVAILABLE");
#endif
 const QString path=QDir(directory).filePath("app-local.key");
 if(!QFileInfo::exists(path)){
  if(QFileInfo::exists(accountDatabasePath))throw std::runtime_error("PROFILE_KEY_RECOVERY_REQUIRED");
  for(const auto& name:{"account.sqlite","credentials.sqlite","control.sqlite"})if(QFileInfo::exists(QDir(directory).filePath(name)))throw std::runtime_error("PROFILE_KEY_RECOVERY_REQUIRED");
  QByteArray random(32,0);for(int i=0;i<32;i+=4){quint32 word=QRandomGenerator::system()->generate();memcpy(random.data()+i,&word,4);}
  QTemporaryFile temporary(QDir(directory).filePath("key-create-XXXXXX"));if(!temporary.open()||temporary.write(random)!=32||!temporary.flush()){random.fill(0);throw std::runtime_error("PROFILE_KEY_UNAVAILABLE");}random.fill(0);
#ifdef Q_OS_UNIX
  if(::fsync(temporary.handle())||::link(QFile::encodeName(temporary.fileName()).constData(),QFile::encodeName(path).constData()))throw std::runtime_error("PROFILE_KEY_UNAVAILABLE");
#else
  temporary.close();if(!MoveFileExW(reinterpret_cast<LPCWSTR>(temporary.fileName().utf16()),reinterpret_cast<LPCWSTR>(path.utf16()),MOVEFILE_WRITE_THROUGH)){const auto error=GetLastError();throw std::runtime_error(std::string("PROFILE_KEY_PUBLISH_WIN32:")+std::to_string(error));}
#endif
 }
 QFileInfo info(path);if(info.isSymLink()||!info.isFile())throw std::runtime_error("PROFILE_KEY_RECOVERY_REQUIRED");
#ifdef Q_OS_WIN
 try{dmash::windowsLocal::requirePrivateFile(path.toStdWString(),false);}
 catch(const std::exception& e){throw std::runtime_error(std::string("PROFILE_KEY_FILE:")+e.what());}
#else
 if(info.ownerId()!=getuid()||(info.permissions()&(QFileDevice::ReadGroup|QFileDevice::WriteGroup|QFileDevice::ExeGroup|QFileDevice::ReadOther|QFileDevice::WriteOther|QFileDevice::ExeOther)))throw std::runtime_error("PROFILE_KEY_RECOVERY_REQUIRED");
#endif
 QFile input(path);if(!input.open(QIODevice::ReadOnly)||input.size()!=32)throw std::runtime_error("PROFILE_KEY_RECOVERY_REQUIRED");return input.readAll();
}
