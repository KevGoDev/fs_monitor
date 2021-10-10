// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdio>

// Helper macro to print debug information
#define MAX_BUF 512
#define DBG_LOG(fmt, ...) {\
	char buf[MAX_BUF]={0}; \
	sprintf_s(buf, MAX_BUF, "[fs_monitorer][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__); \
	OutputDebugStringA(buf);\
}

// Main Entry Point
BOOL APIENTRY DllMain(HMODULE module, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		DBG_LOG("Injected");
		break;
	}
	return TRUE;
}