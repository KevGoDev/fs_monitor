#include <cstdio>
#include <windows.h>

int main(int argc, char** argv) {
    DWORD addr = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    printf("Found Kernel32.LoadLibraryA at %p\n", addr);
    return addr;
}
