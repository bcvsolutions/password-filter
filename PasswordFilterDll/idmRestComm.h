#pragma once

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include <cpprest/json.h>
#include <SubAuth.h>

namespace wh = web::http;
namespace wj = web::json;
namespace cnc = concurrency;
namespace ut = utility;
namespace uc = utility::conversions;

/**
* IdmRequestCont is a class responsible for creating PF request body in JSON format.
*
**/
class IdmRequestCont
{
private:
   const ut::string_t mAccountKey{U("username")};
   const ut::string_t mPasswordKey{U("password")};
   const ut::string_t mSystemKey{U("resource")};
   const ut::string_t mLogIdKey{U("logIdentifier") };
   const ut::string_t mVersionKey{U("version") };

   ut::string_t mAccountName;
   ut::string_t mPassword;
   ut::string_t mSystemName;
   ut::string_t mLogId;

public:
   ~IdmRequestCont();
   void setAccountName(const PUNICODE_STRING& accountName) { mAccountName = pUnicode2String(accountName); }
   void setPassword(const PUNICODE_STRING& password) { mPassword = pUnicode2String(password); }
   bool accountStartsWithPrefix();
   
   void setAccountName(const ut::string_t& accountName) { mAccountName = accountName; }
   void setPassword(const ut::string_t& password) { mPassword = password; }
   void setSystemName(const ut::string_t& systemName) { mSystemName = systemName; }
   void setLogId(const ut::string_t& logId) { mLogId = logId; }

   const ut::string_t& getAccountName() const { return mAccountName; }
   const ut::string_t& getPassword() const { return mPassword; }
   const ut::string_t& getSystemName() const { return mSystemName; }
   const ut::string_t& getLogId() const { return mLogId; }

   ut::string_t toJsonString16() const;
   std::string toJsonString8() const;
   wj::value toJsonObject() const;

private:
   ut::string_t pUnicode2String(const PUNICODE_STRING) const;
};

/**
* IdmResponseCont class parses incoming response from IdM and
* implements the decision which PF action is supposed to be done
* according to the response content.
*/
class IdmResponseCont
{
private:
   // Idm status enum strings 
   constexpr static wchar_t sPolicyValidationFailed[] = U("PASSWORD_DOES_NOT_MEET_POLICY");
   constexpr static wchar_t sSystemNotFound[] = U("PASSWORD_FILTER_SYSTEM_NOT_FOUND");
   constexpr static wchar_t sIdentityNotFound[] = U("PASSWORD_FILTER_IDENTITY_NOT_FOUND");
   constexpr static wchar_t sDefinitionNotFound[] = U("PASSWORD_FILTER_DEFINITION_NOT_FOUND");
   // Idm json keys in the response
   constexpr static wchar_t sErrorKey[] = U("_errors");
   constexpr static wchar_t sStatusEnumKey[] = U("statusEnum");

public:
   enum passFiltAction
   {
      PF_ACT_TRUE,
      PF_ACT_FALSE,
      PF_ACT_CFG_DEFAULT,
      PF_ACT_TRY_AGAIN
   };

private:
   bool mHasIdmContent = false;
   ut::string_t mStatusEnum;
   passFiltAction mPassFiltAction = PF_ACT_CFG_DEFAULT;
   wh::status_code mResultCode;

private:
   bool parseJson(const wj::value& rootObj);
   bool parseJson(const ut::string_t& jsonStr);
   passFiltAction deducePassFiltAction() const;

public:
   IdmResponseCont(const wh::http_response& response);
   const bool hasIdmContent() const { return mHasIdmContent; }
   const ut::string_t& getStatusEnum() const { return mStatusEnum; }
   passFiltAction getPassFiltAction() const { return mPassFiltAction; }
};

/**
* IdmRestComm class implements underlying methods which invoke 
* validation of password policies in Idm
* and then notifies Idm of finished password change in AD
*/
class IdmRestComm
{
private:
   constexpr static wchar_t sIdmContentType[] = U("application/json");
   void addTokenAuthentication(wh::http_headers& head) const;
   bool isSecurityFailure(const wh::http_exception& e);

public:
   IdmRestComm() {};
   cnc::task<wh::http_response> createRequestTask(const wh::method& method, const wh::uri& url, const wj::value& body);
   bool checkIdmPolicies(const IdmRequestCont& body);
   void notifyIdm(const IdmRequestCont& body);
};