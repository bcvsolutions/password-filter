#include "pch.h"
#include <algorithm>
#include "logger.h"


thread_local unsigned long Logger::sSessionId = 0;

Logger::Logger()
{
   readLoggerFileLocation();
   fs::path path(mLogFileFolder);
   std::error_code errCode; // used just not to throw
   if (!fs::exists(path, errCode))
   {
      fs::create_directories(path, errCode); // returns always false -> maybe a bug
   }
   path.append(sLogFileName);

   mFileAppender = std::make_unique<log4cpp::RollingFileAppender>("RollFileAppender", w2s(path.native()).c_str());
   log4cpp::PatternLayout* fileLayout = new log4cpp::PatternLayout; // log4cpp forces us to alloc Layout this way because Appender takes over its ownership
   fileLayout->setConversionPattern("%d{%d-%m-%Y %H:%M:%S,%l} %p %c %m%n");
   mFileAppender->setLayout(fileLayout);
   mCategory.get().setPriority(mDefaultPriority);
   mCategory.get().addAppender(*mEventAppender.get()); // important to pass by ref -> doesn't passes ownership which is required
   mCategory.get().addAppender(*mFileAppender.get()); // important to pass by ref -> doesn't passes ownership which is required
   log(INFO(), "Logging initialized");
}

void Logger::reconfigurePriority(const ut::string_t& priority)
{
   std::string ucPri = uc::utf16_to_utf8(toUpperCase(priority));
   std::vector<lpl> priorities { lpl::DEBUG,lpl::INFO,lpl::WARN,lpl::ERROR };
   for(lpl p : priorities)
   {
      const std::string& priName = log4cpp::Priority::getPriorityName(p);
      if (ucPri.size() == priName.size() && ucPri.compare(priName)==0)
      {
         mLogLevel = p;
         mCategory.get().setPriority(mLogLevel);
         return;
      }
   }
   mCategory.get().setPriority(mDefaultPriority);
}

ut::string_t Logger::toUpperCase(const ut::string_t& str) const
{
   ut::string_t out;
   if (str.empty())
      return out;

   out.reserve(str.size());
   for (auto ch : str)
   {
      out.push_back(std::towupper(ch));
   }
   return out;
}

void Logger::createSessionId() const
{
   std::random_device rd;
   std::mt19937 gen(rd());
   std::uniform_int_distribution<unsigned long> dis;
   sSessionId = dis(gen);
}

unsigned long Logger::getSessionIdValue() const
{
   return sSessionId;
}

std::string Logger::getSessionId() const
{
   return std::to_string(sSessionId);
}

ut::string_t Logger::getSessionIdWide() const
{
   return s2w(getSessionId());
}

const std::string Logger::w2s(const ut::string_t& str)
{
   return uc::utf16_to_utf8(uc::to_utf16string(str));
}

const ut::string_t Logger::s2w(const std::string& str)
{
   return uc::to_string_t(str);
}

void Logger::log(lpl level, const char* fmt, ...)
{
   va_list va;
   va_start(va, fmt);
   std::string msg = formatMessage(fmt, va);
   va_end(va);
   std::string fmtSessionId = formatMessage("%010u", getSessionIdValue());
   std::string out = std::string("\tSessionId: ") + fmtSessionId + " ";
   out += msg;
   removeNewLine(out);
   mCategory.get().log(level, out.c_str());
}

std::string Logger::formatMessage(const char* fmt, va_list va)
{
   size_t size = std::vsnprintf(nullptr, 0, fmt, va);
   if ((int64_t)size < 0)
      return std::string{};

   std::unique_ptr<char[]> buffer(new char[size + 1]); // plus one for '\0'
   std::vsnprintf(buffer.get(), size + 1, fmt, va); // plus one for '\0'
   return std::string(buffer.get(), buffer.get() + size);
}

std::string Logger::formatMessage(const char* fmt, ...)
{
   va_list va;
   va_start(va, fmt);
   std::string out = formatMessage(fmt, va);
   va_end(va);
   return out;
}

std::string& Logger::removeNewLine(std::string& str)
{
   str.erase(std::remove_if(str.begin(), str.end(), [](char ch)
      {
         if (ch == '\r' || ch == '\n')
            return true;
         else
            return false;
      }),
      str.end());
   
   return str;
}

void Logger::readLoggerFileLocation()
{
   const char* logFileFolder = std::getenv(sLogFileEnvVar);
   mLogFileFolder = logFileFolder == nullptr ? sLogFileLoc : logFileFolder;
}