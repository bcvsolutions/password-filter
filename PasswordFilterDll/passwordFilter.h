#pragma once
#include <SubAuth.h>

#ifdef MATHLIBRARY_EXPORTS
#define MATHLIBRARY_API __declspec(dllexport)
#else
#define MATHLIBRARY_API __declspec(dllimport)
#endif

extern "C" {
   MATHLIBRARY_API bool function1();

   MATHLIBRARY_API BOOLEAN InitializeChangeNotify(void);

   MATHLIBRARY_API BOOLEAN __stdcall PasswordFilter(
      _In_ PUNICODE_STRING AccountName,
      _In_ PUNICODE_STRING FullName,
      _In_ PUNICODE_STRING Password,
      _In_ BOOLEAN SetOperation
   );

   MATHLIBRARY_API NTSTATUS __stdcall PasswordChangeNotify(
      _In_ PUNICODE_STRING AccountName,
      _In_ ULONG RelativeId,
      _In_ PUNICODE_STRING Password
   );
}