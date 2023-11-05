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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int PrintUsage(char* argvzero) {
	// add args here
	fprintf(stderr, "Usage: %s\n", argvzero);
	fprintf(stderr, "    --target\n");
	fprintf(stderr, "        Absolute path to target binary to fuzz. \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    --corpus\n");
	fprintf(stderr, "        Initial corpus of files to mutuate. \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    --mutate\n");
	fprintf(stderr, "        Name of file mutation.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    --rounds\n");
	fprintf(stderr, "        Fuzz iterations to execute.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    --seed\n");
	fprintf(stderr, "        Seed for PRNG.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    --functions\n");
	fprintf(stderr, "        Path to functions to use for code coverage.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    --min-mutations\n");
	fprintf(stderr, "        Mininum amount of mutations per sample.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "    --max-mutations\n");
	fprintf(stderr, "        Maximum amount of mutations per sample.\n");
	fprintf(stderr, "\n");
	return 1;
}

BOOL FIRST_RUN = TRUE;

static int POWER_OF_TWO[8]{ 1, 2, 4, 8, 16, 32, 64, 128 };

static int MAGIC_VALS[10][4] = {
	{0xFF},
	{0x7F},
	{0x00},
	{0xFF, 0xFF},
	{0x00, 0x00},
	{0xFF, 0xFF, 0xFF, 0xFF},
	{0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x80},
	{0x00, 0x00, 0x00, 0x40},
	{0xFF, 0xFF, 0xFF, 0x7F},
};


// Mutation Functions
static void MagicByte(char* data, int index) {
	int whichMagic = rand() % (10 - 0) + 0;
	int* magicBytes = MAGIC_VALS[whichMagic];
	int sz = sizeof(MAGIC_VALS[whichMagic]) / sizeof(MAGIC_VALS[whichMagic][0]);
	memcpy(data + index, magicBytes, 4);
}

// Flips A Bit
static char BitFlip(char byte) {
	int whichBit = rand() % (7 + 0);
	return byte ^ POWER_OF_TWO[whichBit];
}

// Flips A Byte
static char ByteFlip(char byte) {
	char randomByte = rand();
	return byte ^ randomByte;
}

// NULL
static char InsertNull(char byte) {
	return 0;
}

// Random Byte Between 0 - 255
static char InsertRandomByte(char byte) {
	return rand()  % (255 + 0);
}


/// 
BYTE SetBreakpoint(HANDLE hProc, UINT64 address);
DWORD RemoveBreakpoint(HANDLE hProc, UINT64 address, BYTE originalByte);
UINT64 GetBaseAddress(HANDLE hProc, const wchar_t* moduleName);
HMODULE GetProcessModule(HANDLE hProc, const wchar_t* exeName);

DWORD LoadInitialBreakPointOffsets(const char* file, HANDLE hProc);

DWORD LoadBreakPoints(HANDLE hProc) {
	DWORD counter = 0;
	FuzzerDB.BreakpointsMutex.lock();
	for (BreakPoint &bp: FuzzerDB.Breakpoints) {
		if (bp.Hit == FALSE) {
			SetBreakpoint(hProc, bp.Address);
			//fprintf(stderr, "[+] Set BreakPoint 0x%p\n", bp.Address);
			counter++;
		}
	}
	FuzzerDB.BreakpointsMutex.unlock();
	return counter;
}
DWORD LoadInitialBreakPointOffsets(const char* file,HANDLE hProc) {
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
			//exit(-1);
			continue;
		}
		b.OriginalByte = OriginalValue;
		FuzzerDB.BreakpointsMutex.lock();
		FuzzerDB.Breakpoints.push_back(b);
		FuzzerDB.BreakpointsMutex.unlock();
		fprintf(stderr, "[+] Set BreakPoint 0x%p\n", b.Address);
		c++;
	}
	fprintf(stderr, "[+] Set %d Breakpoints\n",c);
	FuzzerDB.CoverageData.TotalBreakPoints = c;
	return c;
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
		FuzzerDB.CrashesCount++;
		// First chance: Pass this on to the system. 
		// Last chance: Display an appropriate error. 
		break;

	case EXCEPTION_BREAKPOINT:
		// Loop over currently active breakpoints.
		FuzzerDB.BreakpointsMutex.lock();
		for (BreakPoint &bp : FuzzerDB.Breakpoints) {
			if ((bp.Address == breakAddress) && (bp.Hit == FALSE)) {
				//fprintf(stderr, "We Hit Our BreakPoint! 0x%p\n",bp.Address);
				if (RemoveBreakpoint(hProc, bp.Address, bp.OriginalByte) != 0) {
					fprintf(stderr, "HandleExceptionEvent::RemoveBreakpoint Error %d\n", GetLastError());
					exit(GetLastError());
				}				
				//fprintf(stderr, "Removed BreakPoint! 0x%p\n", bp.Address);
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
				//fprintf(stderr, "RIP: 0x%llx\n", ctx.Rip);
				DWORD64 oldRip = ctx.Rip;
				oldRip -= 1;
				ctx.Rip = oldRip;
				//fprintf(stderr, "Rewinding Rip\n");
				if (!SetThreadContext(hThread, &ctx)) {
					fprintf(stderr, "Failed to get set thread context\n");
					exit(-1);
				}

				if (!GetThreadContext(hThread, &ctx)) {
					fprintf(stderr, "Failed to get thread context\n");
					exit(-1);
				}
				//fprintf(stderr, "RIP: 0x%llx\n", ctx.Rip);
				FuzzerDB.BreakpointsMutex.unlock();
				return TRUE; 				// Return True Because We Handled It.
			}
		}
		FuzzerDB.BreakpointsMutex.unlock();
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
	case 0x406d1388:
		//fprintf(stderr, "Thread Name Exception\n");
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
	if (FIRST_RUN) {
		Sleep(10000);
		DebugActiveProcessStop(proc.pid);
		TerminateProcess(proc.hProc, 0);
		FIRST_RUN = FALSE;
	}
	else {
		Sleep(250);
		DebugActiveProcessStop(proc.pid);
		TerminateProcess(proc.hProc, 0);
	}

}

DWORD CreateProcessAndAttach(const wchar_t* targetWithArgs,const wchar_t* target,const char* breakpointFile, CorpusEntry* mutatedData) {
	STARTUPINFOW sa = {};
	PROCESS_INFORMATION pi = {};
	BOOL RESULT = CreateProcessW(NULL, (LPWSTR)targetWithArgs, NULL, NULL, FALSE, DEBUG_PROCESS | CREATE_NEW_CONSOLE, NULL, NULL, &sa, &pi);
	if (!RESULT) {
		fprintf(stderr, "CreateProcessAndAttach CreateProcessA Error %d\n", GetLastError());
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return -1;
	}
	DEBUG_EVENT dbEvent = {};
	// Checking If we hit ntdll breakpoint to set remaining bps
	BOOL IsFirstExceptionHit = FALSE;
	// Checking if current mutation has been added to corpus
	BOOL addMutatedToCorpus = FALSE;
	StopProc p = { pi.hProcess,pi.dwProcessId };
	HANDLE hThread = CreateThread(NULL, 1024, (LPTHREAD_START_ROUTINE)TerminateProcessThread, &p, NULL, NULL);
	while (1) {
		WaitForDebugEventEx(&dbEvent, INFINITE);
		switch (dbEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			// If We Hit ntdll!LdrpDoDebuggerBreak Set our breakpoints and continue;
			if (!IsFirstExceptionHit) {
				//fprintf(stderr, "[+] Ntdll BreakPoint Hit! Setting Up Coverage.\n");
				if (FuzzerDB.BreakPointsInit) {
					DWORD loaded = LoadBreakPoints(pi.hProcess);
					printf("Loaded %d bps\n", loaded);
				}
				else {
					// Do Initial Setup Get Base Address And Set BreakPoints
					FuzzerDB.BaseAddress = GetBaseAddress(pi.hProcess, target);
					DWORD loaded = LoadInitialBreakPointOffsets(breakpointFile, pi.hProcess);
					FuzzerDB.BreakPointsInit = TRUE;
					printf("Loaded %d bps\n", loaded);
				}
				IsFirstExceptionHit = TRUE;
				ContinueDebugEvent(dbEvent.dwProcessId, dbEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
				continue;
			}
			if (HandleExceptionEvent(pi.hProcess,&dbEvent)){
				if (!addMutatedToCorpus) {
					fprintf(stderr, "[+] Added mutation to corpus.\n");
					CorpusEntry newEntry = { 0 };
					newEntry.Length = mutatedData->Length;
					newEntry.Name = mutatedData->Name;
					newEntry.Data = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newEntry.Length);
					memcpy(newEntry.Data, mutatedData->Data, newEntry.Length);
					newEntry.Name.append(L"M");
					FuzzerDB.CorpusMutex.lock();
					FuzzerDB.Corpus.push_back(newEntry);
					FuzzerDB.CorpusCount++;
					FuzzerDB.CorpusMutex.unlock();
					addMutatedToCorpus = TRUE;
				}
				ContinueDebugEvent(dbEvent.dwProcessId, dbEvent.dwThreadId, DBG_EXCEPTION_HANDLED);
				continue;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			//fprintf(stderr, "Create Thread!\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			//fprintf(stderr, "Create Process\n");
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			//fprintf(stderr, "Exit Thread!\n");
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			//fprintf(stderr, "Exit Process!\n");
			ContinueDebugEvent(dbEvent.dwProcessId, dbEvent.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
			return 0;
		case LOAD_DLL_DEBUG_EVENT:
			//fprintf(stderr, "Load DLL!\n");
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			//fprintf(stderr, "Unload DLL!\n");
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			//fprintf(stderr, "Debug String!\n");
			break;
		case RIP_EVENT:
			//fprintf(stderr, "RIP!\n");
			break;
		default:
			//fprintf(stderr, "??!\n");
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

void Mutate(char* data, size_t length, int minMutate, int maxMutate) {
	int randMax = length;
	int randMin = 0;
	int mutations = rand() % (maxMutate - minMutate) + minMutate;
	//printf("Mutation Applied %d\n",mutations);
	int methods[] = { 0,4 };
	for (int idx = 0; idx < mutations; idx++) {
		//int method = rand() % (4 - 0) + 0;
		int method = 0;
		int flipIndex = rand() % (randMax - randMin) + randMin; // where to flip the bit
		//fprintf(stderr,"Attempting method %d at index %d\n",method,flipIndex);
		if (method == 0) {
			data[flipIndex] = BitFlip(data[flipIndex]);
		}
		else if (method == 1) {
			data[flipIndex] = ByteFlip(data[flipIndex]);
		}
		else if (method == 2) {
			MagicByte(data, flipIndex);
		}
		else if (method == 3) {
			data[flipIndex] = InsertNull(data[flipIndex]);
		}
		else {
			data[flipIndex] = InsertRandomByte(data[flipIndex]);
		}
	}
}

void FuzzLoop(int WorkerId) {
	// Fuzz Round
	FuzzerDB.CorpusMutex.lock();
	DWORD WROTE;
	int CorpusSz = FuzzerDB.Corpus.size();
	int WhichCorpi = rand() % (CorpusSz - 0) + 0;
	// This copies By Default? Not Sure
	CorpusEntry Original = FuzzerDB.Corpus[WhichCorpi];
	CorpusEntry Mutated = { 0 };
	Mutated.Length = Original.Length;
	Mutated.Name = Original.Name;
	Mutated.Data = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Mutated.Length);
	memcpy(Mutated.Data, Original.Data, Mutated.Length);
	FuzzerDB.CorpusMutex.unlock();
	Mutate((char*)Mutated.Data,Mutated.Length, FuzzerDB.minMutation,FuzzerDB.maxMutation);
	wchar_t name_buffer[45];
	swprintf_s(name_buffer, 45, L".\\corpus\\MutatedWorker_%d.bin", WorkerId);
	HANDLE hFile = CreateFileW(name_buffer, GENERIC_ALL,NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Failed to open file error %u\n",GetLastError());
		exit(-1);
	}
	if (!WriteFile(hFile, Mutated.Data, Mutated.Length, &WROTE, NULL)) {
		fprintf(stderr, "Failed to write mutated data to disk\n");
		exit(-1);
	}
	CloseHandle(hFile);
	// Create Process With File As Arg
	wchar_t cmdlineBuffer[56];
	swprintf_s(cmdlineBuffer, 56, L"sumatra .\\corpus\\MutatedWorker_%d.bin", WorkerId);
	//LPTSTR szCmdline = _tcsdup(TEXT("notepad.exe C:\\Users\\lator\\source\\repos\\pasos\\x64\\Debug\\test.txt"));
	CreateProcessAndAttach(cmdlineBuffer,L"sumatra.exe","C:\\Users\\lator\\Desktop\\sumatra_offsets.txt",&Mutated);
	HeapFree(GetProcessHeap(),0,Mutated.Data);
}

void ClearDisplay(){
	COORD coordScreen = { 0, 0 };    // home for the cursor
	DWORD cCharsWritten;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD dwConSize;
	HANDLE hConsole;
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	// Get the number of character cells in the current buffer.
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
	{
		return;
	}

	dwConSize = csbi.dwSize.X * csbi.dwSize.Y;

	// Fill the entire screen with blanks.
	if (!FillConsoleOutputCharacter(hConsole,        // Handle to console screen buffer
		(TCHAR)' ',      // Character to write to the buffer
		dwConSize,       // Number of cells to write
		coordScreen,     // Coordinates of first cell
		&cCharsWritten)) // Receive number of characters written
	{
		return;
	}

	// Get the current text attribute.
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
	{
		return;
	}

	// Set the buffer's attributes accordingly.
	if (!FillConsoleOutputAttribute(hConsole,         // Handle to console screen buffer
		csbi.wAttributes, // Character attributes to use
		dwConSize,        // Number of cells to set attribute
		coordScreen,      // Coordinates of first cell
		&cCharsWritten))  // Receive number of characters written
	{
		return;
	}

	// Put the cursor at its home coordinates.
	SetConsoleCursorPosition(hConsole, coordScreen);
}
void RenderDisplay() {
	ClearDisplay();
	float CoveragePercent = 100 * ((float)FuzzerDB.CoverageData.HitCount / (float)FuzzerDB.CoverageData.TotalBreakPoints);
	printf("Corpus: %llu\n", FuzzerDB.CorpusCount);
	printf("Cases: %llu\n", FuzzerDB.Cases);
	printf("Coverage: %llu/%llu %% %.2f\n", FuzzerDB.CoverageData.HitCount, FuzzerDB.CoverageData.TotalBreakPoints,CoveragePercent);
	printf("Crashes: %llu\n",FuzzerDB.CrashesCount);
}

int main(int argc,char** argv)
{
	char* binary = argv[0];
	argv++;
	// Handle Command Line Args.
	while (*argv != NULL) {
		if (strcmp(*argv, "--target") == 0) {
			argv++;
			if (*argv == NULL)
				return PrintUsage(binary);
			FuzzerDB.TargetBinary = std::string(*argv);
		}
		else if (strcmp(*argv, "--corpus") == 0) {
			argv++;
			if (*argv == NULL)
				return PrintUsage(binary);
			FuzzerDB.CorpusPath = std::string(*argv);
		}
		else if (strcmp(*argv, "--rounds") == 0) {
			argv++;
			if (*argv == NULL)
				return PrintUsage(binary);
			char* ptr;
			uint64_t rounds = strtol(*argv, &ptr, 10);
			if (rounds == 0) {
				return PrintUsage(binary);
			}
			FuzzerDB.Rounds = rounds;
		}
		else if (strcmp(*argv, "--seed") == 0) {
			argv++;
			if (*argv == NULL)
				return PrintUsage(binary);
			char* ptr;
			uint64_t seed = strtol(*argv, &ptr, 10);
			if (seed == 0) {
				return PrintUsage(binary);
			}
			FuzzerDB.Seed = seed;
		}
		/*else if (strcmp(*argv, "--functions") == 0) {
			argv++;
			if (*argv == NULL)
				return PrintUsage(binary);
			assert("TODO handle function file.");
			GLOBAL_CONFIG.functionConfigFile = *argv;
		}*/
		else if (strcmp(*argv, "--min-mutation") == 0) {
			argv++;
			if (*argv == NULL)
				return PrintUsage(binary);
			char* ptr;
			uint64_t minmuts = strtol(*argv, &ptr, 10);
			if (minmuts == 0) {
				return PrintUsage(binary);
			}
			FuzzerDB.minMutation = minmuts;
		}
		else if (strcmp(*argv, "--max-mutation") == 0) {
			argv++;
			if (*argv == NULL)
				return PrintUsage(binary);
			char* ptr;
			uint64_t maxmuts = strtol(*argv, &ptr, 10);
			if (maxmuts == 0) {
				return PrintUsage(binary);
			}
			FuzzerDB.maxMutation = maxmuts;
		}
		else {
			fprintf(stderr, "Error: Unknown Flag %s\n", *argv);
			return PrintUsage(binary);
		}
		argv++;
	}
    fprintf(stderr,"[+] Pasos\n");
	LoadCorpus(L"C:\\corpus\\PDF");
	srand(FuzzerDB.Seed);
	// TODO! Setup Directories .\corpus .\out etc.
	// First Run
	FuzzLoop(0);
	int workers = 2;
	std::vector<std::thread>threads(workers);
	while (1) {
		FuzzLoop(0);
		RenderDisplay();
		/*for (int i = 0; i < workers; i++) {
			threads[i] = std::thread(FuzzLoop, i);
		}
		for (auto& th : threads) {
			th.join();
			// wait for each thread.
			FuzzerDB.Cases++;
		}
		// render display
		RenderDisplay();
		//break;*/
	}
	https://github.com/gamozolabs/mesos/blob/master/mesogen_scripts/ghidra.py fix the script
	CleanUp();
	return 0;
}
