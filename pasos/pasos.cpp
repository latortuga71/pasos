// pasos.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <Psapi.h>
#include <strsafe.h>
#include "pasos.h"
#include <string>
#include <fstream>

BYTE SetBreakpoint(HANDLE hProc, UINT64 address);
DWORD RemoveBreakpoint(HANDLE hProc, UINT64 address, BYTE originalByte);
UINT64 GetBaseAddress(HANDLE hProc, const wchar_t* moduleName);
HMODULE GetProcessModule(HANDLE hProc, const wchar_t* exeName);


DWORD LoadBreakPointOffsets(const char* file,HANDLE hProc) {
	DWORD attributes = GetFileAttributesA(file);
	if (attributes == INVALID_FILE_ATTRIBUTES) {
		fprintf(stderr, "LoadBreakPointOffsets::GetFileAttributes Error File Doesnt Exist Or Is Directory");
		exit(-1);
	}
	int c = 0;
	std::ifstream hFile(file);
	std::vector<std::string> lines;
	std::string line;
	char* end;
	errno = 0;
	while (std::getline(hFile, line)) {
		const char* line_c = line.c_str();
		UINT64 result = strtoull(line_c, &end, 16);
		if (result == 0 && end == line_c) {
			fprintf(stderr, "Not a number\n");
			return -1;
		}
		else if (result == ULLONG_MAX && errno) {
			fprintf(stderr, "value doesnt fit in ulonglong\n");
			return -1;
		}
		BreakPoint b = {};
		b.Hit = FALSE;
		b.Offset = result;
		b.Address = FuzzerDB.BaseAddress + b.Offset;
		// set the breakpoint save original value
		BYTE OriginalValue = SetBreakpoint(hProc, b.Address);
		if (OriginalValue == NULL) {
			fprintf(stderr, "LoadBreakPointOffsets::SetBreakpoint Error Value To Get Original Value\n");
			exit(-1);
		}
		b.OriginalByte = OriginalValue;
		FuzzerDB.Breakpoints.push_back(b);
		fprintf(stderr, "[+] Set BreakPoint 0x%p\n", b.Address);
		c++;
	}
	fprintf(stderr, "[+] Set %d Breakpoints\n",c);
	FuzzerDB.CoverageData.TotalBreakPoints = c;
	return 0;
}

void PrintCorpus() {
	fprintf(stderr, "[+] PrintCorpus::CorpusCount %llu\n", FuzzerDB.CorpusCount);
	for (CorpusEntry& e : FuzzerDB.Corpus) {
		fprintf(stderr, "[->] %ws\n",e.Name.c_str());
		fprintf(stderr, "[");
		for (UINT64 i = 0; i < e.Length; i++) {
			fprintf(stderr, " 0x%02X ", e.Data[i]);
			if (i % 16 == 0 && i != 0) {
				fprintf(stderr, "\n");
			}
		}
		fprintf(stderr, "]\n");
	}
}

DWORD LoadCorpus(const wchar_t* directory) {
	// Loads Files Into FuzzingDB Vector
	// load each file into byte array
	// store byte array in fuzzing db vector
	WIN32_FIND_DATA ffd;
	HANDLE hFind;
	LARGE_INTEGER fileSz = {0,0};
	TCHAR szDir[MAX_PATH];
	size_t length_of_arg;
	DWORD nRead;
	// Check that the input path plus 3 is not longer than MAX_PATH.
   // Three characters are for the "\*" plus NULL appended below.
	StringCchLength(directory, MAX_PATH, &length_of_arg);

	if (length_of_arg > (MAX_PATH - 3))
	{
		_tprintf(TEXT("\nDirectory path is too long.\n"));
		exit(-1);
	}
	//_tprintf(TEXT("\nTarget directory is %ws\n\n"), directory);
	// Prepare string for use with FindFile functions.  First, copy the
	// string to a buffer, then append '\*' to the directory name.
	StringCchCopy(szDir, MAX_PATH, directory);
	StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

	hFind = FindFirstFileW(szDir, &ffd);
	if (hFind == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "LoadCorpus::FindFirstFileW Error %d\n",GetLastError());
		exit(-1);
	}
	do {
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			continue;
		}
		else {
			fileSz.LowPart = ffd.nFileSizeLow;
			fileSz.HighPart = ffd.nFileSizeHigh;
			BYTE* FileBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSz.QuadPart);
			std::wstring path = directory;
			path.append(L"\\");
			path.append(ffd.cFileName);
			HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,NULL);
			if (hFile == INVALID_HANDLE_VALUE) {
				fprintf(stderr, "LoadCorpus::CreateFileW Error %d\n", GetLastError());
				exit(-1);
			}
			if (!ReadFile(hFile, FileBuffer, fileSz.QuadPart, &nRead, NULL)) {
				fprintf(stderr, "LoadCorpus::ReadFile Error %d\n", GetLastError());
				exit(-1);
			}
			CorpusEntry entry = { FileBuffer,fileSz.QuadPart,path};
			path.clear();
			FuzzerDB.Corpus.push_back(entry);
			FuzzerDB.CorpusCount++;
			CloseHandle(hFile);
		}
	} while (FindNextFile(hFind, &ffd) != 0);
	FindClose(hFind);
	return 0;
}

char* globalOriginalData = NULL;

BOOL HandleExceptionEvent(HANDLE hProc,DEBUG_EVENT* dbEvent) {
	UINT64 breakAddress = (UINT64)dbEvent->u.Exception.ExceptionRecord.ExceptionAddress;
	switch (dbEvent->u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		fprintf(stderr, "[!!!] HolyShit A Crash? At 0x%llx\n",breakAddress);
		// First chance: Pass this on to the system. 
		// Last chance: Display an appropriate error. 
		break;

	case EXCEPTION_BREAKPOINT:
		// Loop over currently active breakpoints.
		for (BreakPoint &bp : FuzzerDB.Breakpoints) {
			if ((bp.Address == breakAddress) && (bp.Hit == FALSE)) {
				fprintf(stderr, "We Hit Our BreakPoint! 0x%p\n",bp.Address);
				if (RemoveBreakpoint(hProc, bp.Address, bp.OriginalByte) != 0) {
					fprintf(stderr, "HandleExceptionEvent::RemoveBreakpoint Error %d\n", GetLastError());
					exit(GetLastError());
				}				
				fprintf(stderr, "Removed BreakPoint! 0x%p\n", bp.Address);
				bp.Hit = TRUE;
				FuzzerDB.CoverageData.HitCount++;
				
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbEvent->dwThreadId);
				if (hThread == INVALID_HANDLE_VALUE){
					fprintf(stderr, "Failed to get thread handle\n");
					exit(-1);
				}
				CONTEXT ctx = {0};
				ctx.ContextFlags = CONTEXT_ALL;
				if (!GetThreadContext(hThread, &ctx)) {
					fprintf(stderr, "Failed to get thread context\n");
					exit(-1);
				}
				fprintf(stderr, "RIP: 0x%llx\n", ctx.Rip);
				DWORD64 oldRip = ctx.Rip;
				oldRip -= 1;
				ctx.Rip = oldRip;
				fprintf(stderr, "Rewinding Rip\n");
				if (!SetThreadContext(hThread, &ctx)) {
					fprintf(stderr, "Failed to get set thread context\n");
					exit(-1);
				}

				if (!GetThreadContext(hThread, &ctx)) {
					fprintf(stderr, "Failed to get thread context\n");
					exit(-1);
				}
				fprintf(stderr, "RIP: 0x%llx\n", ctx.Rip);
				return TRUE; 				// Return True Because We Handled It.
			}
		}
		fprintf(stderr, "[!] We Hit A BreakPoint We Did Not Set??? 0x%llx\n",breakAddress);
		return TRUE;

	case EXCEPTION_DATATYPE_MISALIGNMENT:
		fprintf(stderr, "Err Alignment\n");
		// First chance: Pass this on to the system. 
		// Last chance: Display an appropriate error. 
		break;

	case EXCEPTION_SINGLE_STEP:
		fprintf(stderr, "Err single step\n");
		// First chance: Update the display of the 
		// current instruction and register values. 
		break;

	case DBG_CONTROL_C:
		fprintf(stderr, "Err Ctrl C\n");
		// First chance: Pass this on to the system. 
		// Last chance: Display an appropriate error. 
		break;

	default:
		fprintf(stderr, "Err ??? 0x%x At 0x%llx\n", dbEvent->u.Exception.ExceptionRecord.ExceptionCode,breakAddress);
		// Handle other exceptions. 
		break;
	}
	return FALSE;
}
struct StopProc {
	HANDLE hProc;
	DWORD pid;
};

void TerminateProcessThread(StopProc proc) {
	Sleep(5000);
	printf("Terminating Debugged Process\n");
	DebugActiveProcessStop(proc.pid);
	//TerminateProcess(proc.hProc,0);
}

DWORD CreateProcessAndAttach(const wchar_t* targetWithArgs,const wchar_t* target,const char* breakpointFile) {
	STARTUPINFOW sa = {};
	PROCESS_INFORMATION pi = {};
	BOOL RESULT = CreateProcessW(NULL, (LPWSTR)targetWithArgs, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS | CREATE_NEW_CONSOLE, NULL, NULL, &sa, &pi);
	if (!RESULT) {
		fprintf(stderr, "CreateProcessAndAttach CreateProcessA Error %d\n", GetLastError());
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}
	DEBUG_EVENT dbEvent = {};
	BOOL IsFirstExceptionHit = FALSE;
	StopProc p = { pi.hProcess,pi.dwProcessId };
	HANDLE hThread = CreateThread(NULL, 1024, (LPTHREAD_START_ROUTINE)TerminateProcessThread, &p, NULL, NULL);
	while (1) {
		WaitForDebugEventEx(&dbEvent, INFINITE);
		switch (dbEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			if (!IsFirstExceptionHit) {
				// Do Initial Setup Get Base Address And Set BreakPoints
				fprintf(stderr, "[+] Ntdll BreakPoint Hit! Setting Up Coverage.\n");
				FuzzerDB.BaseAddress = GetBaseAddress(pi.hProcess, target);
				LoadBreakPointOffsets(breakpointFile,pi.hProcess);
				IsFirstExceptionHit = TRUE;
				ContinueDebugEvent(dbEvent.dwProcessId, dbEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
				continue;
			}
			if (HandleExceptionEvent(pi.hProcess,&dbEvent)){
				ContinueDebugEvent(dbEvent.dwProcessId, dbEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
				// rewind rip?
				continue;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			fprintf(stderr, "Create Thread!\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			fprintf(stderr, "Create Process\n");
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			fprintf(stderr, "Exit Thread!\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			fprintf(stderr, "Exit Process!\n");
			return 0;
		case LOAD_DLL_DEBUG_EVENT:
			fprintf(stderr, "Load DLL!\n");
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			fprintf(stderr, "Unload DLL!\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			fprintf(stderr, "Debug String!\n");
			break;
		case RIP_EVENT:
			fprintf(stderr, "RIP!\n");
			break;
		default:
			fprintf(stderr, "??!\n");
			break;
		}
		// DBG_CONTINUE;
		ContinueDebugEvent(dbEvent.dwProcessId, dbEvent.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
	}
	return 0;
}

BYTE SetBreakpoint(HANDLE hProc,UINT64 address)  {
	char buffer[1] = {0x00};
	char int3[1] = { 0xCC};
	SIZE_T nRead,nWrote = 0;
	DWORD oldProtect = 0;
	if (!VirtualProtectEx(hProc,(LPVOID) address, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		fprintf(stderr, "SetBreakpoint::VirtualProtectEx Error: %u\n", GetLastError());
		return NULL;
	}
	if (!ReadProcessMemory(hProc, (LPCVOID)address, buffer, sizeof(buffer), &nRead)) {
		fprintf(stderr, "SetBreakpoint::ReadProcessMemory Error: %u\n", GetLastError());
		return NULL;
	}
	if (!WriteProcessMemory(hProc, (LPVOID)address, int3, sizeof(int3), &nWrote)) {
		fprintf(stderr, "SetBreakpoint::WriteProcessMemory Error: %u\n", GetLastError());
		return NULL;
	}
	if (!VirtualProtectEx(hProc, (LPVOID)address, sizeof(buffer), oldProtect, &oldProtect)) {
		fprintf(stderr, "SetBreakpoint::VirtualProtectEx Error: %u\n", GetLastError());
		return NULL;
	}
	return buffer[0];
}

DWORD RemoveBreakpoint(HANDLE hProc, UINT64 address,BYTE byte) {
	char buffer[1] = { 0x00 };
	char og[1] = { byte };
	SIZE_T nRead, nWrote = 0;
	DWORD oldProtect = 0;
	if (!VirtualProtectEx(hProc, (LPVOID)address, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		fprintf(stderr, "RemoveBreakpoint::VirtualProtectEx Error: %u\n", GetLastError());
		return -1;
	}
	if (!ReadProcessMemory(hProc, (LPCVOID)address, buffer, sizeof(buffer), &nRead)) {
		fprintf(stderr, "RemoveBreakpoint::ReadProcessMemory Error: %u\n", GetLastError());
		return -1;
	}
	if (!WriteProcessMemory(hProc, (LPVOID)address, (LPCVOID)og, 1, &nWrote)) {
		fprintf(stderr, "Removereakpoint::WriteProcessMemory Error: %u\n", GetLastError());
		return -1;
	}
	if (!ReadProcessMemory(hProc, (LPCVOID)address, buffer, sizeof(buffer), &nRead)) {
		fprintf(stderr, "RemoveBreakpoint::ReadProcessMemory Error: %u\n", GetLastError());
		return -1;
	}
	if (!VirtualProtectEx(hProc, (LPVOID)address, sizeof(buffer), oldProtect, &oldProtect)) {
		fprintf(stderr, "RemoveBreakpoint::VirtualProtectEx Error: %u\n", GetLastError());
		return -1;
	}
	return 0;
}


HMODULE GetProcessModule(HANDLE hProc, const wchar_t* exeName) {
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;
	if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)){
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++){
			TCHAR szModName[MAX_PATH];
			if (GetModuleFileNameEx(hProc, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))){
				std::wstring wstrModName = szModName;
				std::wstring wstrModContain = exeName;
				if (wstrModName.find(wstrModContain) != std::string::npos)
					return hMods[i];
			}
		}
	}
	return NULL;
}

UINT64 GetBaseAddress(HANDLE hProc,const wchar_t* moduleName) {
	HMODULE exeHandle = GetProcessModule(hProc, moduleName);
	if (exeHandle == NULL) {
		fprintf(stderr, "GetProcessModule Error %u\n", GetLastError());
		return 0;
	}
	UINT64 baseAddress = (UINT64)exeHandle;
	CloseHandle(exeHandle);
	printf("[+] Base Address 0x%p\n", baseAddress);
	return baseAddress;
}

void CleanUp() {
	fprintf(stderr, "[+] CleanUp\n");
	//Free Corpus
	for (CorpusEntry& e : FuzzerDB.Corpus) {
		HeapFree(GetProcessHeap(), 0, e.Data);
		FuzzerDB.CorpusCount--;
	}
	FuzzerDB.Corpus.clear();
	fprintf(stderr, "[+] Freed Corpus\n");
}

void Fuzz() {
	// SET SEED AND TIMEOUT SECONDS FOR SEPERATE TERMIANTE PROCESS THREAD
	// use a seed for deterministic mutations
	// Randomly Choose Something In Corpus
	// Mutate it
	// Write it to disk in ./tmp directory
	// CreateProcess With That FullPath To Mutation As Argument
	// Breakpoints will be loaded 
	// set timeout on process debug for x seconds
	// if breakpoints hit move mutated on disk data to in memory corpus.
	// when process exits repeat process
	// to increase "speed" you have a way to fork? and create multiple instances of this thing?
}

int main()
{
	//00007ff6`38dfe654 <- 00007ff6` 38df e654 notepad!AnsiWriteFile (int __cdecl AnsiWriteFile(void *,unsigned int,unsigned long,void *,unsigned long))
	//00007ff6`3024e654	<- 00007ff6` 3024 e654 notepad!AnsiWriteFile (int __cdecl AnsiWriteFile(void *,unsigned int,unsigned long,void *,unsigned long))	
	// 00007ff6`3024 0000 00007ff6`30278000
	// Get Base Address = 00007ff6`30240000 Add Offsets
	//https://learn.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop
	// https://www.timdbg.com/posts/writing-a-debugger-from-scratch-part-2/
	// Load Initial Corpus Into Memory
    fprintf(stderr,"[+] Pasos\n");
	LoadCorpus(L"C:\\corpus");
	PrintCorpus();

	// Create Process Debug SetBreakPoints.
	//	LPTSTR szCmdline = _tcsdup(TEXT("notepad.exe C:\\Users\\lator\\source\\repos\\pasos\\x64\\Debug\\test.txt")); C:\Users\lator\Desktop
	LPTSTR szCmdline = _tcsdup(TEXT("notepad.exe C:\\Users\\lator\\source\\repos\\pasos\\x64\\Debug\\test.txt"));
	CreateProcessAndAttach(szCmdline,L"notepad.exe","C:\\Users\\lator\\Desktop\\offsets.txt");

	// How Do We Fuzz Loop?
	// CreateProcess With Mutated Data As Input
	// 

	https://github.com/gamozolabs/mesos/blob/master/mesogen_scripts/ghidra.py fix the script
	CleanUp();
	return 0;
}
