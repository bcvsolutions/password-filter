#include "pch.h"
#include "version.h"
#include "configuration.h"
#include "logger.h"



extern Logger gLogger;

std::mutex Configuration::sMutex; // static def

Configuration::Configuration()
{
   try
   {
      mVersion = uc::to_string_t(std::string(sVersion));
      readConfigFilePath();
      isConfigFileChanged(); // just init file change date
      initConfigFile();
      initConfigMonitor();
   }
   catch (const std::exception& e)
   {
      mConfigurationInitialized.store(false);
      gLogger.log(Logger::ERROR(), "An unexpected error occurred during Configuration reading: %s\n Password filter is not properly initialized", e.what());
      return;
   }
}

bool Configuration::proveKeyPresence(const wj::value& obj, const ut::string_t& key, bool (wj::value::*hasMethod)(const ut::string_t&) const, bool willThrow)
{
   if (!(obj.*hasMethod)(key))
   {
      std::string msg = Logger::formatMessage("Requested JSON object \"%s\" was not found", Logger::w2s(key).c_str());
      gLogger.log(Logger::WARN(), msg.c_str());
      if (willThrow)
         throw wj::json_exception(msg.c_str());
      return false;
   }
   return true;
}


void Configuration::initConfigFile()
{
   try
   {
      std::vector<ut::string_t> multivalueStringBuf;
      mConfigurationInitialized.store(false);
      std::fstream cfgFile(mConfigFilePath.c_str(), std::ios_base::in);
      if (cfgFile.fail())
      {
         gLogger.log(Logger::ERROR(), "Opening of the configuration \"%s\" file failed", mConfigFilePath.c_str());
         return;
      }

      wj::value rootObj = wj::value::parse(cfgFile);
      proveKeyPresence(rootObj, mRestBaseUrlKey, &wj::value::has_array_field, true);
      auto restBaseUrls = rootObj[mRestBaseUrlKey].as_array();
      multivalueStringBuf.clear();
      std::transform(restBaseUrls.begin(), restBaseUrls.end(), std::back_inserter(multivalueStringBuf), [](const wj::value& item)
         {
            return item.as_string();
         });
      mRestBaseUrlVec = multivalueStringBuf;

      proveKeyPresence(rootObj, mRestCheckUrlKey, &wj::value::has_string_field, true);
      mRestCheckUrl = rootObj[mRestCheckUrlKey].as_string();

      proveKeyPresence(rootObj, mRestNotifyUrlKey, &wj::value::has_string_field, true);
      mRestNotifyUrl = rootObj[mRestNotifyUrlKey].as_string();

      proveKeyPresence(rootObj, mTokenKey, &wj::value::has_string_field, true);
      mToken = rootObj[mTokenKey].as_string();

      proveKeyPresence(rootObj, mIgnoreCertificateKey, &wj::value::has_boolean_field, true);
      mIgnoreCertificate = rootObj[mIgnoreCertificateKey].as_bool();

      proveKeyPresence(rootObj, mConnectionAttemptsKey, &wj::value::has_integer_field, true);
      mConnectionAttempts = rootObj[mConnectionAttemptsKey].as_number().to_uint32();

      proveKeyPresence(rootObj, mConnectionTimeoutMsKey, &wj::value::has_integer_field, true);
      mConnectionTimeoutMs = rootObj[mConnectionTimeoutMsKey].as_number().to_uint32();

      proveKeyPresence(rootObj, mSystemIdKey, &wj::value::has_string_field, true);
      mSystemId = rootObj[mSystemIdKey].as_string();

      proveKeyPresence(rootObj, mAllowChangeByDefaultKey, &wj::value::has_boolean_field, true);
      mAllowChangeByDefault = rootObj[mAllowChangeByDefaultKey].as_bool();

      proveKeyPresence(rootObj, mSkippedAccPrefixKey, &wj::value::has_array_field, true);
      auto skippedPrefixes = rootObj[mSkippedAccPrefixKey].as_array();
      multivalueStringBuf.clear();
      std::transform(skippedPrefixes.begin(), skippedPrefixes.end(), std::back_inserter(multivalueStringBuf), [](const wj::value& item)
         {
            return item.as_string();
         });
      mSkippedAccPrefixVec = multivalueStringBuf;

      
      proveKeyPresence(rootObj, mLogLevelKey, &wj::value::has_string_field, true);
      mLogLevel = rootObj[mLogLevelKey].as_string();

      proveKeyPresence(rootObj, mPasswordFilterEnabledKey, &wj::value::has_boolean_field, true);
      mPasswordFilterEnabled = rootObj[mPasswordFilterEnabledKey].as_bool();

      mConfigurationInitialized.store(true);

      // special workaroud how to reinit logger level from default value
      gLogger.reconfigurePriority(mLogLevel);

      gLogger.log(Logger::INFO(), "Configuration has been successfully initialized from the file: \"%s\"", mConfigFilePath.c_str());
   }
   catch (const std::exception& ex)
   {
      gLogger.log(Logger::ERROR(), "Parser of the configuration file \"%s\" encountered the following exception: %s", mConfigFilePath.c_str(), ex.what());
   }
   printLogFileContent();
}

void Configuration::initConfigMonitor()
{
   pplx::task<void> monThread([this]()
      {
         try
         {
            std::fstream file{};
            while (true)
            {
               readConfigFilePath();
               
               if (!isConfigFileChanged())
               {
                  std::this_thread::sleep_for(std::chrono::seconds(mCfgFileCheckPeriodSec));
                  continue;
               }
               initConfigFile();
            }
         }
         catch (const std::exception& e)
         {
            gLogger.log(Logger::ERROR(), "The task monitoring changes in configuration file encountered an exception: %s", e.what());
         }
      });
     mMonitorThread = std::move(monThread);
     gLogger.log(Logger::INFO(), "Configuration monitoring thread successfully started");
 }

void Configuration::readConfigFilePath()
{
   std::error_code ec;
   const char* configFileName = std::getenv(sConfigFileEnvVar);
   if (configFileName == nullptr || !fs::exists(configFileName, ec))
   {
      configFileName = sConfigFilePath;
   }

   if (mConfigFilePath.compare(configFileName) != 0)
   {
      mConfigFilePath.clear();
      mConfigFilePath.insert(0, configFileName);
      mLastFileChange = fs::file_time_type(); // force file reload
      gLogger.log(Logger::INFO(), "Configuration file will be loaded from the path %s", configFileName);
   }
}

bool Configuration::isConfigFileChanged()
{
   std::error_code ec;
   fs::file_time_type fileChanged = fs::last_write_time(mConfigFilePath.c_str(), ec);
   if (ec) // error reading config file
   {
      mLastFileChange = fs::file_time_type(); // force file reload
      return false;
   }
   if (mLastFileChange < fileChanged)
   {
      mLastFileChange = fileChanged;
      return true;
   }
   return false;
}

void Configuration::printLogFileContent() const
{
   if (mRestBaseUrlVec.empty())
      gLogger.log(Logger::DEBUG(), "%s:", Logger::w2s(mRestBaseUrlKey).c_str());
   else
   {
      for (const ut::string_t& url : mRestBaseUrlVec)
         gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mRestBaseUrlKey).c_str(), Logger::w2s(url).c_str());
   }

   gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mRestCheckUrlKey).c_str(), Logger::w2s(mRestCheckUrl).c_str());
   gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mRestNotifyUrlKey).c_str(), Logger::w2s(mRestNotifyUrl).c_str());
   gLogger.log(Logger::DEBUG(), "%s: %u", Logger::w2s(mConnectionAttemptsKey).c_str(), mConnectionAttempts);
   gLogger.log(Logger::DEBUG(), "%s: %u", Logger::w2s(mConnectionTimeoutMsKey).c_str(), mConnectionTimeoutMs);
   gLogger.log(Logger::DEBUG(), "%s: EXCLUDED FROM LOG", Logger::w2s(mTokenKey).c_str());

   std::string boolString = mIgnoreCertificate ? Logger::w2s(U("true")) : Logger::w2s(U("false"));
   gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mIgnoreCertificateKey).c_str(), boolString.c_str());

   gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mSystemIdKey).c_str(), Logger::w2s(mSystemId).c_str());

   boolString = mAllowChangeByDefault ? Logger::w2s(U("true")) : Logger::w2s(U("false"));
   gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mAllowChangeByDefaultKey).c_str(), boolString.c_str());

   gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mLogLevelKey).c_str(), Logger::w2s(mLogLevel).c_str());

   if (mSkippedAccPrefixVec.empty())
      gLogger.log(Logger::DEBUG(), "%s:", Logger::w2s(mSkippedAccPrefixKey).c_str());
   else
   {
      for (const ut::string_t& item : mSkippedAccPrefixVec)
         gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mSkippedAccPrefixKey).c_str(), Logger::w2s(item).c_str());
   }

   boolString = mPasswordFilterEnabled ? Logger::w2s(U("true")) : Logger::w2s(U("false"));
   gLogger.log(Logger::DEBUG(), "%s: %s", Logger::w2s(mPasswordFilterEnabledKey).c_str(), boolString.c_str());
}

