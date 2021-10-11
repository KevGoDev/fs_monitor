#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include "macros.h"

class Process {
private:
	DWORD id;
	std::wstring name;
	bool m_is_64bit = true;
public:

	Process(std::wstring name, DWORD pid = 0, bool is_64bit=true);
	~Process();
	/// <summary>
	/// Resolves processes with a given name within a certain timeout.
	/// </summary>
	/// <param name="name">Name of the processes to fetch</param>
	/// <param name="timeout">Timeout in milliseconds before aborting, can be -1 to wait undefinitely</param>
	/// <returns>A vector of heap allocated processes instances</returns>
	static std::vector<Process*> get_pids_by_name(std::wstring name, int timeout=-1);

	/// <summary>
	/// Gets the address of LoadLibraryA depending on architecture of remote process
	/// </summary>
	/// <returns>The address of LoadLibraryA. It is not validated.</returns>
	FARPROC get_LoadLibraryA_address();

	/// <summary>
	/// Injects a dll into the process
	/// </summary>
	/// <param name="dll_path">Full path of the dll to inject</param>
	/// <returns>Returns whether it succeeded or not</returns>
	bool inject_dll(const char* dll_path);
	bool is_64bit() { return this->m_is_64bit; }
};

