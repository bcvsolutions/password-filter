#pragma once

#include <time.h>
#include <cpprest/filestream.h>

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/RollingFileAppender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/NDC.hh"
#include "log4cpp/PropertyConfigurator.hh"
#include "log4cpp/NTEventLogAppender.hh"


namespace ut = utility;
namespace uc = utility::conversions;
namespace fs = std::filesystem;

/**
* Logger class encapsulates log4cpp library used for logging password filter
* 
*/
class Logger
{
public:
   using lpl = log4cpp::Priority::PriorityLevel;
private:
   static inline const char* sLogFileEnvVar = "BCV_PWF_LOG_FILE_FOLDER";
   static inline const char* sLogFileLoc = "c:/CzechIdM/PasswordFilter/log/";
   static inline const char* sLogFileName = "PasswordFilterLog.log";
   static constexpr const char* sEventSourceName = "CzechIdMPasswordFilter";
   const lpl mDefaultPriority = log4cpp::Priority::PriorityLevel::DEBUG;

   thread_local static unsigned long sSessionId;
   lpl mLogLevel = mDefaultPriority;
   std::reference_wrapper<log4cpp::Category> mCategory = std::ref(log4cpp::Category::getRoot());
   std::unique_ptr<log4cpp::Appender> mEventAppender = std::make_unique<log4cpp::NTEventLogAppender>("NTEventLogAppender", sEventSourceName);
   std::unique_ptr<log4cpp::Appender> mFileAppender;
   std::string mLogFileFolder;

   ut::string_t toUpperCase(const ut::string_t& str) const;
   void readLoggerFileLocation();

public:
   Logger();
   log4cpp::Category& operator() () { return mCategory; }
   void reconfigurePriority(const ut::string_t& priority);
   void createSessionId() const;
   std::string getSessionId() const;
   ut::string_t getSessionIdWide() const;
   void log(lpl level, const char* fmt, ...); // follows the same signature as log form log4cpp

   static std::string formatMessage(const char* fmt, va_list va);
   static std::string formatMessage(const char* fmt, ...);
   static std::string& removeNewLine(std::string& str); // in place new line removing
   static const std::string w2s(const ut::string_t& str);
   static const ut::string_t s2w(const std::string& str);
   static lpl ERROR() { return lpl::ERROR; }
   static lpl WARN() { return lpl::WARN; }
   static lpl INFO() { return lpl::INFO; }
   static lpl DEBUG() { return lpl::DEBUG; }
};