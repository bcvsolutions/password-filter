// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "logger.h"

extern Logger gLogger;


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
       gLogger.log(Logger::INFO(), "Inside Dll main - DLL_PROCESS_ATTACH: PID %u", GetCurrentProcessId());
       break;
    case DLL_THREAD_ATTACH:
       break;
    case DLL_THREAD_DETACH:
       break;
    case DLL_PROCESS_DETACH:
       gLogger.log(Logger::INFO(), "Inside Dll main - DLL_PROCESS_DETACH: PID %u", GetCurrentProcessId());
       break;
    default:
       break;
    }
    return TRUE;
}

