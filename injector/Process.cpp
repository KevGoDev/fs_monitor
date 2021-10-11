#include "Process.h"
#include <chrono>
#include <ctime>   
#include <cmath>
#include <cassert>


Process::Process(std::wstring name, DWORD pid, bool is_64bit) {
    this->name = std::wstring(name);
    this->id = pid;
    this->m_is_64bit = is_64bit;
}
Process::~Process() {

}
FARPROC Process::get_LoadLibraryA_address() {
    assert(this->id >= 0);
    // If the target process is 64 bit then we simply return the global address of LoadLibraryA
    if (this->m_is_64bit) {
        return GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    }
    // The target process is 32-bit so we must call our process helper to get the WOW64 address of LoadLibraryA
    // We get the working directory to be able to call our process helper
    char working_dir[MAX_BUF] = { 0 };
    if (!GetCurrentDirectoryA(MAX_BUF-1, working_dir)) {
        DBG_LOG("[ERROR]: Could not retrieve current working directory while resolving LoadLibraryA. Aborting...\n");
        return NULL;
    }
    
    // We create a new process for the ProcessHelper32
    std::string exe_path = std::string(working_dir) + "\\ProcessHelper32.exe";
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    ZeroMemory(&startup_info, sizeof(startup_info));
    startup_info.cb = sizeof(startup_info);
    ZeroMemory(&process_info, sizeof(process_info));
    BOOL process_created = CreateProcessA(exe_path.c_str(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, &startup_info, &process_info);
    if (process_created) {
        // We wait for the process to return
        WaitForSingleObject(process_info.hProcess, INFINITE);
        DWORD process_return = 0;
        BOOL res = GetExitCodeProcess(process_info.hProcess, &process_return);
        if (!res) {
            DBG_LOG("Error while getting process returned value: %d\n", GetLastError());
        }
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);

        // We return the address given by ProcessHelper32
        DBG_LOG("ProcessHelper32 returned %04x\n", process_return);
        return (FARPROC)process_return;
    }
    else {
        DBG_LOG("Could not call ProcessHelper32 at (%s), received error code: %d. Aborting...\n", exe_path.c_str(), GetLastError());
        return NULL;
    }
}

bool Process::inject_dll(const char* dll_path) {
    assert(this->id >= 0);
    DBG_LOG("Injecting %s on pid %d\n", dll_path, this->id);
    // We open a handle to the remote process
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, this->id);
    SIZE_T written_bytes = 0;
    // We resolve the address of LoadLibraryA
    PTHREAD_START_ROUTINE loadlibrary_address = (PTHREAD_START_ROUTINE)this->get_LoadLibraryA_address();
    if (loadlibrary_address <= 0) {
        DBG_LOG("Address of LoadLibraryA is invalid. Addr: %p\n", loadlibrary_address);
        return false;
    }
    // We write the full path of the dll inside the remote process
    LPVOID dllpath_address = VirtualAllocEx(process_handle, NULL, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(process_handle, dllpath_address, dll_path, strlen(dll_path) + 1, &written_bytes);
    // We create a thread inside the remote process that executes our injected dll
    CreateRemoteThread(process_handle, NULL, 1024, loadlibrary_address, dllpath_address, 0, 0);
    return true;
}

std::vector<Process*> Process::get_pids_by_name(std::wstring name, int timeout) {
    int elapsed = 0;
    auto start_time = std::chrono::steady_clock::now();
    std::vector<Process*> processes;
    while (timeout == -1 || elapsed < timeout) {
        // Look for process by name
        HANDLE snapshot;
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        // Gets a snapshot of the entire system (https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        // No processes running. This is not normal and might be a permission issue.
        if (!Process32First(snapshot, &pe32)) {
            DBG_LOG("Couldn't fetch processes on the system.\n");
            CloseHandle(snapshot);
            return processes;
        }
        do {
            if (!wcscmp(pe32.szExeFile, name.c_str())) {
                // We found our process, we save its informations such as process id and architecture
                DBG_LOG("Found process %ws with PID %d", pe32.szExeFile, pe32.th32ProcessID);
                DWORD pid = pe32.th32ProcessID;
                BOOL is_wow64 = false;
                HANDLE process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pe32.th32ProcessID);
                IsWow64Process(process_handle, &is_wow64);
                CloseHandle(process_handle);
                bool is_64bit = is_wow64 == false; // wow64 = 32bit emulator
                Process* p = new Process(name, pid, is_64bit);
                processes.push_back(p);
            }
        } while (Process32Next(snapshot, &pe32));

        CloseHandle(snapshot);
        // If we found something then we can return
        if (processes.size() > 0) {
            return processes;
        }
        
        // Update timer
        Sleep(25);
        auto current_time = std::chrono::steady_clock::now();
        elapsed = std::round(std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count());
    }
    DBG_LOG("Couldn't find the process within the time allocation.");
    return processes;
}