#pragma once
#ifndef PASOS_H

#define PASOS_H

#include <windows.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <mutex>

struct Crashes {
	UINT64 Address;
	BYTE* Data;
};

struct Coverage {
	UINT64 TotalBreakPoints;
	UINT64 HitCount;
};

struct BreakPoint {
	BOOL Hit;
	BYTE OriginalByte;
	UINT64 Offset;
	UINT64 Address;
};

struct CorpusEntry {
	BYTE* Data;
	UINT64 Length;
	std::wstring Name; 
};

class GlobalData {
public:
	std::string TargetBinary;
	std::string CorpusPath;
	std::vector<BreakPoint> Breakpoints;
	std::mutex BreakpointsMutex;
	std::mutex CorpusMutex;
	BOOL BreakPointsInit = FALSE;
	UINT64 Cases; // How Many Test Cases Ran;
	UINT64 CrashesCount; // Amount Of Crashes
	UINT64 BaseAddress;
	UINT64 CorpusCount;
	UINT64 Seed;
	UINT64 Rounds;
	int minMutation;
	int maxMutation;
	Coverage CoverageData;
	Crashes CrashesData;
	std::vector<CorpusEntry>Corpus;
};


GlobalData FuzzerDB = {};
BOOL HitNtDllLdrpDoDebuggerBreak = FALSE;

#endif // !PASOS_H


#ifdef PASOS_IMPLEMENTATION
// Pasos API Implementation







#endif
