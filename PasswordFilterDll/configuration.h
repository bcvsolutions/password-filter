#pragma once
#include<mutex>
#include <filesystem>
#include <cpprest/json.h>
#include <ppltasks.h>

namespace ut = utility;
namespace uc = utility::conversions;
namespace wj = web::json;



/**
* Configuration class takes care of maintaining and providing of the password filter configuration.
* Configuration file is periodically checked for the change of its date of change. If a change is detected it is reloaded again.
* The periodical check is serviced by a special thread which is started at the object creation.
*/
class Configuration
{
private:
   const constexpr static char* sConfigFileEnvVar = "BCV_PWF_CONFIG_FILE_PATH";
   const constexpr static char* sConfigFilePath = "c:/CzechIdM/PasswordFilter/etc/PasswordFilterConfig.cfg";
   const unsigned int mCfgFileCheckPeriodSec = 3;
   // JSON keys
   const ut::string_t mSystemIdKey{ U("systemId") };
   const ut::string_t mRestBaseUrlKey{ U("restBaseUrl") };
   const ut::string_t mRestCheckUrlKey{ U("restCheckUrl") };
   const ut::string_t mRestNotifyUrlKey{ U("restNotifyUrl") };

   const ut::string_t mTokenKey{ U("token") };
   const ut::string_t mForbiddenInitCharsKey{ U("forbiddenInitChars") };

   const ut::string_t mConnectionAttemptsKey{ U("connectionAttempts") };
   const ut::string_t mConnectionTimeoutMsKey{ U("connectionTimeoutMs") };

   const ut::string_t mIgnoreCertificateKey{ U("ignoreCertificate") };
   const ut::string_t mAllowChangeByDefaultKey{ U("allowChangeByDefault") };
   
   const ut::string_t mPasswordFilterEnabledKey{ U("passwordFilterEnabled") };
   const ut::string_t mLogLevelKey{ U("logLevel") };

   // value keepers
   ut::string_t mSystemId;
   std::vector<ut::string_t> mRestBaseUrlVec;
   ut::string_t mRestCheckUrl;
   ut::string_t mRestNotifyUrl;
   uint32_t mConnectionTimeoutMs = 30000;
   uint32_t mConnectionAttempts = 1;

   ut::string_t mToken;
   ut::string_t mForbiddenInitChars;
   ut::string_t mLogLevel;

   ut::string_t mVersion;
   
   bool mPasswordFilterEnabled = true;
   bool mIgnoreCertificate = false;
   bool mAllowChangeByDefault = true;

   std::atomic<bool> mConfigurationInitialized = false;
   static std::mutex sMutex;

   pplx::task<void> mMonitorThread;
   std::filesystem::file_time_type mLastFileChange;
   std::string mConfigFilePath;

public:
   Configuration();
   const bool getConfigurationInitialised() { return mConfigurationInitialized.load(); }

   const std::vector<ut::string_t>& getRestBaseUrlVec() { return mRestBaseUrlVec; }
   const ut::string_t& getRestCheckUrl() { return mRestCheckUrl; }
   const ut::string_t& getRestNotifyUrl() { return mRestNotifyUrl; }
   const ut::string_t& getToken() { return mToken; }
   const uint32_t& getConnectionTimeoutMs() { return mConnectionTimeoutMs; }
   const uint32_t& getConnectionAttempts() { return mConnectionAttempts; }
   const bool getIgnoreCertificate() { return mIgnoreCertificate; }
   const ut::string_t& getSystemId() { return mSystemId; }
   const ut::string_t& getForbiddenInitChars() { return mForbiddenInitChars; }
   const bool getAllowChangeByDefault() {return mAllowChangeByDefault; }
   const ut::string_t getLogLevel() { return mLogLevel; }
   const bool getPasswordFilterEnabled() { return mPasswordFilterEnabled; }
   
   const ut::string_t& getVersion() { return mVersion; }

   static bool proveKeyPresence(const wj::value& obj, const ut::string_t& key, bool (wj::value::* hasMethod)(const ut::string_t&) const, bool willThrow=false);
   void initConfigFile();

private:
   void initConfigMonitor();
   void readConfigFilePath();
   bool isConfigFileChanged();
};

