#include <cstdio>
#include <iostream>
#include "macros.h"
#include "Process.h"

int main() {
    // We get our current working directory
    char working_dir[MAX_BUF] = { 0 };
    if (!GetCurrentDirectoryA(MAX_BUF, working_dir)) {
        DBG_LOG("[ERROR]: Could not retrieve current working directory. Aborting...");
        DBG_LOG("Press any key to exit...");
        getchar();
        return 0;
    }
    // We build the paths to our payloads
    std::string dll32 = std::string(working_dir) + "\\payload32.dll";
    std::string dll64 = std::string(working_dir) + "\\payload64.dll";
    DBG_LOG("Payload path for 32bit: %s", dll32.c_str());
    DBG_LOG("Payload path for 64bit: %s", dll64.c_str());

    // We get the target process name from the user
    std::string process_name;
    DBG_LOG("Process to monitor(Example: Notepad.exe): ");
    std::cin >> process_name;
    std::wstring wprocess_name = std::wstring(process_name.begin(), process_name.end());
    
    // We fetch the processes with our specified process name
    DBG_LOG("Waiting for process '%ws'.", wprocess_name.c_str());
    std::vector<Process*> processes = Process::get_pids_by_name(wprocess_name, -1);
    if (processes.size() > 0) {
        DBG_LOG("We found %d with the name '%ws'", processes.size(), wprocess_name.c_str());
        for (auto process : processes) {
            bool res = false;
            if (process->is_64bit()) {
                DBG_LOG("Injecting in 64bit mode");
                res = process->inject_dll(dll64.c_str());
            }
            else {
                DBG_LOG("Injecting in 32bit mode");
                res = process->inject_dll(dll32.c_str());
            }
            DBG_LOG("Injection result: %s", (res ? "Success" : "Failure"));
        }
    }
    else {
        DBG_LOG("We couldn't find any process with the name '%ws'", wprocess_name.c_str());
    }

    DBG_LOG("Press any key to exit...");
    getchar();
    return 0;
}
