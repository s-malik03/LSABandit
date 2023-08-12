#pragma once
#include <DbgHelp.h>
#pragma comment (lib, "Dbghelp.lib")

// CallbackHelper object for MiniDumpWriteDump

typedef struct CallbackHelper
{
	LPVOID dumpBuffer;
	DWORD bytesRead;
} CallbackHelper, * pCallbackHelper;

/*
* A callback function used with MiniDumpWriteDump API
* Recives extended minidump information
* @param CallbackParam - An application defined parameter
* @param CallbackInput - A pointer to MINIDUMP_CALLBACK_INPUT (defined in DbgHelp.h) that specified extended minidump information
* @param CallbackOutput - A pointer to MINIDUMP_CALLBACK_OUTPUT (defined in DbgHelp.h) that recives application defined information from the callback function
* @return BOOL - TRUE or FALSE
* For more information see MSDN documantation - https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/nc-minidumpapiset-minidump_callback_routine
*/

BOOL CALLBACK minidumpCallback(
	PVOID callbackParam,
	const PMINIDUMP_CALLBACK_INPUT callbackInput,
	PMINIDUMP_CALLBACK_OUTPUT callbackOutput
);

/*
* Calls MiniDumpWriteDump directly on the handle and provided PID
* Dumps to file on disk
* @param handle - the handle to the process to be dumped
* @param PID - the PID of the process to be dumped
*/

void dump(HANDLE* handle, DWORD PID);

/*
* Calls MiniDumpWriteDump and uses callback to dump contents into memory
* The contents are then encrypted and dumped into a file
* @param hTarget - the handle to the target process
* @param TargetPid - the pid of the target process
*/

BOOL MiniDump(HANDLE hTarget, int TargetPid, HANDLE FileHandle);