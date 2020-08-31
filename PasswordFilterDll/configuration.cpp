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
      mLastFileChange = std::filesystem::last_write_time(sConfigFilePath);
      initConfigFile();
      initConfigMonitor();
   }
   catch (const std::exception& e)
   {
      mConfigurationInitialized.store(false);
      gLogger.log(Logger::ERROR(), "An unexpected error occurred during Configuration reading: %s\n Password filter is not properly initialized", e.what());
      return;
   }
   gLogger.log(Logger::INFO(), "Configuration successfully initialized");
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
      mConfigurationInitialized.store(false);
      std::fstream cfgFile(sConfigFilePath, std::ios_base::in);
      if (cfgFile.fail())
      {
         gLogger.log(Logger::ERROR(), "Opening of the configuration \"%s\" file failed", sConfigFilePath);
         return;
      }

      wj::value rootObj = wj::value::parse(cfgFile);
      proveKeyPresence(rootObj, mRestBaseUrlKey, &wj::value::has_array_field, true);
      auto restBaseUrls = rootObj[mRestBaseUrlKey].as_array();
      std::transform(restBaseUrls.begin(), restBaseUrls.end(), std::back_inserter(mRestBaseUrlVec), [](const wj::value& item)
         {
            return item.as_string();
         });

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

      proveKeyPresence(rootObj, mForbiddenInitCharsKey, &wj::value::has_string_field, true);
      mForbiddenInitChars = rootObj[mForbiddenInitCharsKey].as_string();
      
      proveKeyPresence(rootObj, mLogLevelKey, &wj::value::has_string_field, true);
      mLogLevel = rootObj[mLogLevelKey].as_string();

      proveKeyPresence(rootObj, mPasswordFilterEnabledKey, &wj::value::has_boolean_field, true);
      mPasswordFilterEnabled = rootObj[mPasswordFilterEnabledKey].as_bool();

      mConfigurationInitialized.store(true);

      // special workaroud how to reinit logger level from default value
      gLogger.reconfigurePriority(mLogLevel);

      gLogger.log(Logger::INFO(), "Configuration has been successfully initialized from file: \"%s\"", sConfigFilePath);
   }
   catch (const std::exception& ex)
   {
      gLogger.log(Logger::ERROR(), "Parser of the configuration file \"%s\" encountered the following exception: %s", sConfigFilePath, ex.what());
   }
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
               std::filesystem::file_time_type fileChanged = std::filesystem::last_write_time(sConfigFilePath);
               if (!(mLastFileChange < fileChanged))
               {
                  std::this_thread::sleep_for(std::chrono::seconds(mCfgFileCheckPeriodSec));
                  continue;
               }
               initConfigFile();
               mLastFileChange = fileChanged;
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
