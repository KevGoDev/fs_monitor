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

	Process(std::wstring name, DWORD pid = 0);
	~Process();

	/// <summary>
	/// Waits until the process is found on the system and assigns its process id
	/// </summary>
	/// <param name="timeout">Time in miliseconds to wait before abandoning. -1 to wait undefinitely</param>
	/// <returns>Process id</returns>
	DWORD wait_for_process(int timeout = -1);

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

