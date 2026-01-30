#pragma once
#include "helpers.h"
#include "PEB.h"

__forceinline PVOID GetModule(_In_ DWORD pModuleNameHash)
{
#if defined(_WIN64)
    PVOID pPeb = (PVOID)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = *(PPEB_LDR_DATA*)((PBYTE)pPeb + 0x18);
#elif defined(_WIN32)
    PVOID pPeb = (PVOID)__readfsdword(0x30);
    PPEB_LDR_DATA pLdr = *(PPEB_LDR_DATA*)((PBYTE)pPeb + 0x0C);
#else
#error Unknown architecture
#endif

    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    for (PLIST_ENTRY pEntry = pListHead->Flink; pEntry != pListHead; pEntry = pEntry->Flink)
    {
        PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pEntry;
        if (pDte->BaseDllName.Buffer && HashStringDjb2(pDte->BaseDllName.Buffer) == pModuleNameHash)
            return pDte->DllBase;
    }

    return NULL;
}

__forceinline PVOID GetFunction(_In_ PVOID pModuleBase, _In_ DWORD lpProcNameHash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY exportDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + exportDir.VirtualAddress);
    PDWORD pdwNames = (PDWORD)((PBYTE)pModuleBase + pExportDir->AddressOfNames);
    PWORD  pwOrdinals = (PWORD)((PBYTE)pModuleBase + pExportDir->AddressOfNameOrdinals);
    PDWORD pdwFunctions = (PDWORD)((PBYTE)pModuleBase + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR pszName = (LPCSTR)((PBYTE)pModuleBase + pdwNames[i]);
        if (HashStringDjb2(pszName) == lpProcNameHash) {
            DWORD dwFunctionRVA = pdwFunctions[pwOrdinals[i]];
            if (dwFunctionRVA >= exportDir.VirtualAddress &&
                dwFunctionRVA < exportDir.VirtualAddress + exportDir.Size) {
                return NULL;
            }
            return (PVOID)((PBYTE)pModuleBase + dwFunctionRVA);
        }
    }

    return NULL;
}