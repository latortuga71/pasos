#pragma once
#ifndef PASOS_H

#define PASOS_H

#include <windows.h>
#include <stdint.h>
#include <string>
#include <vector>

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
	std::vector<BreakPoint> Breakpoints;
	UINT64 Cases; // How Many Test Cases Ran;
	UINT64 CrashesCount; // Amount Of Crashes
	UINT64 BaseAddress;
	UINT64 CorpusCount;
	Coverage CoverageData;
	std::vector<CorpusEntry>Corpus;
};


GlobalData FuzzerDB = {};
BOOL HitNtDllLdrpDoDebuggerBreak = FALSE;

#endif // !PASOS_H


#ifdef PASOS_IMPLEMENTATION
// Pasos API Implementation







#endif
