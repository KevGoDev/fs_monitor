// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdio>
#include <string>
#include <winternl.h>


// Helper macro to print debug information
#define MAX_BUF 512
#define DBG_LOG(fmt, ...) {\
	char buf[MAX_BUF]={0}; \
	sprintf_s(buf, MAX_BUF, "[fs_monitorer][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__); \
	OutputDebugStringA(buf);\
}

// This value is used during the IAT hooking process to make sure the ordinal is valid
#if _WIN64
	#define INVALID_ORDINAL 0x8000000000000000
#else
	#define INVALID_ORDINAL 0x80000000
#endif

/* NT function definition for GetFilePath */
typedef NTSTATUS(*NtQueryObject_proto)(
	_In_opt_ HANDLE Handle,
	_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength,
	_Out_opt_ PULONG ReturnLength
	);
NtQueryObject_proto ResolvedNtQueryObject = nullptr;

/* Undocumented API: http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FOBJECT_INFORMATION_CLASS.html */
#define ObjectNameInformation 1

/// <summary>
/// Gets the file path from a file/pipe handle
/// </summary>
/// <param name="hFile">Handle to the file/pipe</param>
/// <returns>A heap allocated wchar array</returns>
LPWSTR GetFilePath(HANDLE hFile) {
	void* temp_obj_name = malloc(MAX_BUF);
	ZeroMemory(temp_obj_name, MAX_BUF);
	ULONG returnedLength;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;
	if (ResolvedNtQueryObject == nullptr) {
		ResolvedNtQueryObject = (NtQueryObject_proto)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
		if (ResolvedNtQueryObject == nullptr) {
			DBG_LOG("Could not resolve NtQueryObject");
			free(temp_obj_name);
			return NULL;
		}
	}
	status = ResolvedNtQueryObject(hFile, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, temp_obj_name, MAX_BUF, &returnedLength);
	void* obj_name = malloc(MAX_BUF);
	ZeroMemory(obj_name, MAX_BUF);
	// We skip 8 bytes forward to ignore unicode structure
	memcpy(obj_name, ((char*)temp_obj_name + 8), MAX_BUF - 8);
	free(temp_obj_name);
	return (LPWSTR)obj_name;
}

// Globals for original functions address and signature.
typedef FILE* (*proto_fopen)(const char*, const char*);
typedef errno_t(*proto_fopen_s)(FILE**, const char*, const char*);
typedef size_t(*proto_fread)(void*, size_t, size_t, FILE*);
typedef size_t(*proto_fwrite)(void*, size_t, size_t, FILE*);
typedef HANDLE(*proto_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(*proto_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(*proto_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
proto_fopen original_fopen = nullptr;
proto_fopen_s original_fopen_s = nullptr;
proto_fread original_fread = nullptr;
proto_fwrite original_fwrite = nullptr;
proto_CreateFileW original_CreateFileW = nullptr;
proto_CreateFileA original_CreateFileA = nullptr;
proto_ReadFile original_ReadFile = nullptr;

// Hook functions
HANDLE CreateFileW_hook(LPCWSTR filename, DWORD des_acces, DWORD shr_mode, LPSECURITY_ATTRIBUTES sec_atr, DWORD creation, DWORD flags, HANDLE htemplate) {
	// We call the original function to get the actual result
	HANDLE handle = original_CreateFileW(filename, des_acces, shr_mode, sec_atr, creation, flags, htemplate);
	// We log the filename of the file we performed the operation on
	DBG_LOG("[CALL]: Creating/Opening file %ws with handle %p", filename, handle);
	// We return the original function's result
	return handle;
}
HANDLE CreateFileA_hook(LPCSTR Filename, DWORD DesiredAccess, DWORD ShareMode, LPSECURITY_ATTRIBUTES SecAttribs, DWORD CreationDisp, DWORD Flags, HANDLE Template) {
	HANDLE handle = original_CreateFileA(Filename, DesiredAccess, ShareMode, SecAttribs, CreationDisp, Flags, Template);
	DBG_LOG("[CALL]: Creating/Opening file %s with handle %p", Filename, handle);
	return handle;
}
FILE* fopen_hook(const char* filename, const char* mode) {
	FILE* file = original_fopen(filename, mode);
	DBG_LOG("[CALL]: Opening file %s with mode %s and stream %p", filename, mode, file);
	return file;
}
errno_t fopen_s_hook(FILE** stream, const char* filename, const char* mode) {
	errno_t err = original_fopen_s(stream, filename, mode);
	DBG_LOG("[CALL]: Opening file %s with mode %s and stream %p", filename, mode, *stream);
	return err;
}
size_t fread_hook(void* ptr, size_t size, size_t count, FILE* stream) {
	LPWSTR obj_name = GetFilePath(stream);
	if (obj_name != NULL) {
		DBG_LOG("[CALL]: Reading %d bytes on file %ws", size * count, obj_name);
		free(obj_name);
	}
	else {
		DBG_LOG("[CALL]: Reading %d bytes unknown file", size * count);
	}
	return original_fread(ptr, size, count, stream);
}
size_t fwrite_hook(void* buffer, size_t size, size_t count, FILE* stream) {
	LPWSTR obj_name = GetFilePath(stream);
	if (obj_name != NULL) {
		DBG_LOG("[CALL]: Writing %d bytes on file %ws", size * count, obj_name);
		free(obj_name);
	}
	else {
		DBG_LOG("[CALL]: Writing %d bytes unknown file", size * count);
	}
	return original_fwrite(buffer, size, count, stream);
}
BOOL ReadFile_hook(HANDLE hFile, LPVOID lpBuffer, DWORD nb_bytes, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
	LPWSTR obj_name = GetFilePath(hFile);
	if (obj_name != NULL) {
		DBG_LOG("[CALL]: Reading %d bytes on file %ws", nb_bytes, obj_name);
		free(obj_name);
	}
	else {
		DBG_LOG("[CALL]: Reading %d bytes unknown file", nb_bytes);
	}
	return original_ReadFile(hFile, lpBuffer, nb_bytes, lpNumberOfBytesRead, lpOverlapped);
}


/// <summary>
/// Reroutes a function to another function.
/// </summary>
/// <param name="function_name">Name of the function to reroute.</param>
/// <param name="addr_new_fn">Address of the new function we want function_name to point to.</param>
/// <returns>Returns the original address of the function to reroute. Returns NULL if we couldn't find the function.</returns>
DWORD_PTR hook_IAT(std::string function_name, void* addr_new_fn) {
	// Get the base address of the current module
	LPVOID image_base = GetModuleHandleA(NULL);
	if (image_base == NULL) {
		DBG_LOG("[ERROR]: Image base is null");
		return NULL;
	}
	// Read PE Headers from image
	// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
	PIMAGE_DOS_HEADER dos_headers = (PIMAGE_DOS_HEADER)image_base;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_base + dos_headers->e_lfanew);
	// Get imports descriptor
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = NULL;
	IMAGE_DATA_DIRECTORY imports_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(imports_directory.VirtualAddress + (DWORD_PTR)image_base);
	// Iterate through each descriptor(module) and get their import table
	while (import_descriptor->Name != NULL) {
		// Load current module to get its import table
		LPCSTR library_name = (LPCSTR)import_descriptor->Name + (DWORD_PTR)image_base;
		HMODULE library = LoadLibraryA(library_name);
		DBG_LOG("Processing module %s", library_name);
		if (library) {
			// Read import table from current module
			PIMAGE_THUNK_DATA orig_first_thunk = NULL, first_thunk = NULL;
			orig_first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)image_base + import_descriptor->OriginalFirstThunk);
			first_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)image_base + import_descriptor->FirstThunk);
			while (orig_first_thunk->u1.AddressOfData != NULL) {
				PIMAGE_IMPORT_BY_NAME function_import = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)image_base + orig_first_thunk->u1.AddressOfData);
				// We must be careful about the validity of AddressOfData
				if (orig_first_thunk->u1.AddressOfData <= INVALID_ORDINAL) {
					DBG_LOG("\tFound function: %s", function_import->Name);
				}
				// Check if address of data is valid, some imports will set most significant bit to 1 which we can't read
				if (orig_first_thunk->u1.AddressOfData <= INVALID_ORDINAL && std::string(function_import->Name).compare(function_name) == 0) {
					// We need to set the import table protection to RW in order to edit it
					DWORD old_protection = 0, void_protect = 0;
					VirtualProtect((LPVOID)(&first_thunk->u1.Function), 8, PAGE_READWRITE, &old_protection);
					// We save original address of the hooked function
					DWORD_PTR original_address = first_thunk->u1.Function;
					// We hook the function
					first_thunk->u1.Function = (DWORD_PTR)addr_new_fn;
					// We restore region protection on the import table
					VirtualProtect((LPVOID)(&first_thunk->u1.Function), 8, old_protection, &void_protect);
					return original_address;
				}
				orig_first_thunk++;
				first_thunk++;
			}
		}
		import_descriptor++;
	}
	return NULL;
}

/// <summary>
/// Prints to Debug status information about the hooking process of a function.
/// </summary>
/// <param name="function_name">Name of the function we attempted to hook.</param>
/// <param name="old_addr">Original address returned by hook_IAT.</param>
void dbgPrintHookStatus(std::string function_name, void* old_addr) {
	if (old_addr != NULL) {
		DBG_LOG("[LOG]: Hooked %s, old address: %p", function_name.c_str(), old_addr);
	}
	else {
		DBG_LOG("[ERROR]: Failed to hook %s", function_name.c_str());
	}
}

DWORD WINAPI main_thread(void*) {
	// We save the original address inside our global variable, the function should be hooked
	original_CreateFileW = (proto_CreateFileW)hook_IAT("CreateFileW", CreateFileW_hook);
	original_fopen = (proto_fopen)hook_IAT("fopen", fopen_hook);
	original_fopen_s = (proto_fopen_s)hook_IAT("fopen_s", fopen_s_hook);
	original_fread = (proto_fread)hook_IAT("fread", fread_hook);
	original_fwrite = (proto_fwrite)hook_IAT("fwrite", fwrite_hook);
	original_ReadFile = (proto_ReadFile)hook_IAT("ReadFile", ReadFile_hook);
	original_CreateFileA = (proto_CreateFileA)hook_IAT("CreateFileA", CreateFileA_hook);
	// We print debug information about our hook result
	dbgPrintHookStatus("fopen", (void*)original_fopen);
	dbgPrintHookStatus("fopen_s", (void*)original_fopen_s);
	dbgPrintHookStatus("fread", (void*)original_fread);
	dbgPrintHookStatus("fwrite", (void*)original_fwrite);
	dbgPrintHookStatus("ReadFile", (void*)original_ReadFile);
	dbgPrintHookStatus("CreateFileA", (void*)original_CreateFileA);
	dbgPrintHookStatus("CreateFileW", (void*)original_CreateFileW);
	return TRUE;
}


// Main Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		DBG_LOG("Injected");
		CreateThread(nullptr, 0, main_thread, hModule, 0, nullptr);
		break;
	}
	return TRUE;
}