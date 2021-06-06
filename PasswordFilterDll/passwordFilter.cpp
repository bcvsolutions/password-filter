#include "pch.h" // precompiled headers - hast to be the first include

#include "logger.h"
#include "configuration.h"
#include "passwordFilter.h"
#include "idmRestComm.h"


/****Global objects****/
Logger gLogger;
Configuration gConfiguration{};


/*
   Password filter init function
   informs AD that password filter is correctly initialized.
   We always return true because it depends on configuration setting
   which can be fixed during runtime.
*/
BOOLEAN __stdcall InitializeChangeNotify(void)
{
   gLogger.log(Logger::DEBUG(), "Calling InitializeChangeNotify");
   return true;
}

/**
* Called before every password change to validate 
* that password policy requirements are fulfilled.
*/
BOOLEAN __stdcall PasswordFilter(
   _In_ PUNICODE_STRING AccountName,
   _In_ PUNICODE_STRING FullName,
   _In_ PUNICODE_STRING Password,
   _In_ BOOLEAN SetOperation
)
{
   gLogger.createSessionId();
   gLogger.log(Logger::DEBUG(), "Calling PasswordFilter - password policy validation");

   if (!gConfiguration.getConfigurationInitialised())
   {
      gLogger.log(Logger::INFO(), "Account: %s - Password filter is not configured properly. Password validation is skipped and the change is APPROVED", 
         Logger::w2s(IdmRequestCont::pUnicode2String(AccountName)).c_str());
      return true;
   }

   if (!gConfiguration.getPasswordFilterEnabled())
   {
      gLogger.log(Logger::INFO(), "Account: %s - Password filter is disabled. Password validation is skipped and the change is APPROVED",
         Logger::w2s(IdmRequestCont::pUnicode2String(AccountName)).c_str());
      return true;
   }

   IdmRequestCont cont{};
   cont.setAccountName(AccountName);
   cont.setPassword(Password);
   cont.setSystemName(gConfiguration.getSystemId());
   cont.setLogId(gLogger.getSessionIdWide());

   if (cont.accountStartsWithPrefix())
   {
      gLogger.log(Logger::INFO(), "Account: %s - Account starts with a reserved string. Password validation is skipped and the change is APPROVED",
         Logger::w2s(cont.getAccountName()).c_str());
      return true;
   }

   IdmRestComm idmRest{};
   bool retval = idmRest.checkIdmPolicies(cont);
   return retval;
}

/**
* Called after password has been changed on AD.
* It notifies IdM that password is supposed to be changed on related system.
*/
NTSTATUS __stdcall PasswordChangeNotify(
   _In_ PUNICODE_STRING AccountName,
   _In_ ULONG RelativeId,
   _In_ PUNICODE_STRING Password
)
{
   gLogger.createSessionId();
   gLogger.log(Logger::DEBUG(),"Calling PasswordChangeNotify");

   if (!gConfiguration.getConfigurationInitialised())
   {
      gLogger.log(Logger::INFO(), "Account: %s - Password filter is not configured properly. IdM notification is skipped",
         Logger::w2s(IdmRequestCont::pUnicode2String(AccountName)).c_str());
      return STATUS_SUCCESS;
   }

   if (!gConfiguration.getPasswordFilterEnabled())
   {
      gLogger.log(Logger::INFO(), "Account: %s - Password filter is disabled. IdM notification is skipped",
         Logger::w2s(IdmRequestCont::pUnicode2String(AccountName)).c_str());
      return STATUS_SUCCESS;
   }
   
   if (AccountName == NULL || Password == NULL)
   {
      gLogger.log(Logger::INFO(), "Account: %s - Account or password is not specified. IdM notification is skipped",
         Logger::w2s(IdmRequestCont::pUnicode2String(AccountName)).c_str());
      return STATUS_SUCCESS;
   }

   IdmRequestCont cont{};
   cont.setAccountName(AccountName);
   cont.setPassword(Password);
   cont.setSystemName(gConfiguration.getSystemId());
   cont.setLogId(gLogger.getSessionIdWide());

   if (cont.accountStartsWithPrefix())
   {
      gLogger.log(Logger::INFO(), "Account: %s - Account starts with a reserved string. IdM notification is skipped",
         Logger::w2s(cont.getAccountName()).c_str());
      return STATUS_SUCCESS;
   }

   IdmRestComm idmRest{};
   idmRest.notifyIdm(cont);

   return STATUS_SUCCESS;
}