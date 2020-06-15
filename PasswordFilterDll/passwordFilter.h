#pragma once
#include <SubAuth.h>

#ifdef PASSWORDFILTERDLL_EXPORTS
#define PASSWORDFILTERDLL_API __declspec(dllexport)
#else
#define PASSWORDFILTERDLL_API __declspec(dllimport)
#endif

extern "C" {

   PASSWORDFILTERDLL_API BOOLEAN InitializeChangeNotify(void);

   PASSWORDFILTERDLL_API BOOLEAN __stdcall PasswordFilter(
      _In_ PUNICODE_STRING AccountName,
      _In_ PUNICODE_STRING FullName,
      _In_ PUNICODE_STRING Password,
      _In_ BOOLEAN SetOperation
   );

   PASSWORDFILTERDLL_API NTSTATUS __stdcall PasswordChangeNotify(
      _In_ PUNICODE_STRING AccountName,
      _In_ ULONG RelativeId,
      _In_ PUNICODE_STRING Password
   );
}