#include <string>

// password filter specific
#include <SubAuth.h>

// rest sdk headers
//#include <cpprest/http_headers.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>


#include "pch.h"
#include "passwordFilter.h"


using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::json;


/*
   test function
*/
bool function1()
{
   http_client client(U("http://localhost:3000/#/modules"));
   uri_builder uriBuilder(U("/available-services"));

   utility::string_t pass(U("admin"));
   utility::string_t login(U("admin"));
   web::http::client::credentials cred(login, pass);
   
   web::http::client::http_client_config clientConfig();
   
   

   auto request = client.request(methods::GET, uriBuilder.to_string());
   



   return true;
}

/*
   Password filter init function
*/
BOOLEAN __stdcall InitializeChangeNotify(void)
{
   return TRUE;
}

/*
   Called before password change to validate password
*/
BOOLEAN __stdcall PasswordFilter(
   _In_ PUNICODE_STRING AccountName,
   _In_ PUNICODE_STRING FullName,
   _In_ PUNICODE_STRING Password,
   _In_ BOOLEAN SetOperation
)
{
   return TRUE;
}

/*
   Called after password has been changed
*/
NTSTATUS __stdcall PasswordChangeNotify(
   _In_ PUNICODE_STRING AccountName,
   _In_ ULONG RelativeId,
   _In_ PUNICODE_STRING Password
)
{
   return STATUS_SUCCESS;
}