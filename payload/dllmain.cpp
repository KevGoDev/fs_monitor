// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// Main Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        break;
    }
    return TRUE;
}

