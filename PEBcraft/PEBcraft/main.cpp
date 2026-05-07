#include "PEBcraft.h"

#pragma code_seg(".text")
int main() {
    PVOID pKernel32 = GetModule(HASH("kernel32.dll"));
    if (!pKernel32) return 1;

    PVOID pLoadLibraryA = GetFunction(pKernel32, HASH("LoadLibraryA"));
    if (!pLoadLibraryA) return 1;

    auto fpLoadLibraryA = WIN_API(LoadLibraryA)pLoadLibraryA;

    // Write code here
    HMODULE hUser32 = fpLoadLibraryA(XOR("User32.dll"));
    if (!hUser32) return 1;

    auto fpMessageBoxA = WIN_API(MessageBoxA)GetFunction(hUser32, HASH("MessageBoxA"));
    if (!fpMessageBoxA) return 1;
    
    fpMessageBoxA(NULL, XOR("Message"), XOR("Title"), MB_OK | MB_ICONINFORMATION);

    return 0;
}
#pragma code_seg()