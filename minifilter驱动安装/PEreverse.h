#pragma once
#include "stdafx.h"
#include <iostream>   
#include <list>   
#include <numeric>   
#include <algorithm>   
#include <VECTOR>
using namespace std;
struct PackNames
{
	string Name;
	string Sig;
};
//创建一个list容器的实例LISTINT   
typedef list<string> PEInportTableList;
typedef list<PackNames> PackNamesList;
#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))
typedef enum _PEREVERSESTATUS {
	PEREVERSESTATUS_SUCCESS = 0, 
	PEREVERSESTATUS_ERRORMAPOFVIEW,
	PEREVERSESTATUS_ERRORPEFILE
} NPEREVERSESTATUS;
typedef enum _FILELEVEL {
	FILELEVEL_NORMAL = 0,
	FILELEVEL_HIGHT,
	FILELEVEL_ERROR
} NFILELEVEL;
class PEreverse {
public:
	DWORD RVA2Offset(PIMAGE_NT_HEADERS pNTHeader, DWORD dwExpotRVA);

	bool CheckName(const char * iName);

	int GetFileLevel(CString Patch, bool ScanPack/*, bool IsDll*/);

	string GetFilePackName(HANDLE FileHandle);

	int GetFileImportTable(CString Patch, PEInportTableList & TableList, string &PackName);

};
//派大星
//怎么了海绵宝宝
//我不想写了派大星、
//那我们就抄吧 UC @ maxkunes
class CFindPatternEx {
private:
	
	PBYTE Buffer;
	HANDLE hModule;
	DWORD dwFindPattern(DWORD dwAddress, DWORD dwLength, const char* szPattern)
	{
		const char* pat = szPattern;
		DWORD firstMatch = NULL;
		for (DWORD pCur = dwAddress; pCur < dwLength; pCur++)
		{
			if (!*pat) return firstMatch;
			if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat)) {
				if (!firstMatch) firstMatch = pCur;
				if (!pat[2]) return firstMatch;
				if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?') pat += 3;
				else pat += 2;
			}
			else {
				pat = szPattern;
				firstMatch = 0;
			}
		}
		return NULL;
	}

	bool FindPatternSimplified(DWORD dwAddress, DWORD dwLength, const char* szPattern) {
		//DWORD result = dwFindPattern(dwAddress, dwAddress + dwLength, szPattern);
		//PBYTE bresult = (PBYTE)result;
		//bresult += Offset;
		return dwFindPattern(dwAddress, dwAddress + dwLength, szPattern) ?  true: false;
	}
public:
	CFindPatternEx(HANDLE T_hModule) {
		/*
		hModule = CreateFileA(ModulePath.c_str(), GENERIC_READ, // open for reading
			0, // do not share
			NULL, // default security
			OPEN_EXISTING, // existing file only
			FILE_ATTRIBUTE_NORMAL, // normal file
			NULL);
			*/
		hModule = T_hModule;
		if (hModule == INVALID_HANDLE_VALUE)
			printf("Failed to open a handle to the dll Error %d\n", GetLastError());
		Buffer = (PBYTE)VirtualAlloc(NULL, GetFileSize(hModule, NULL), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!Buffer)
			printf("Could not Allocate %d bytes of memory\n", GetFileSize(hModule, NULL));
		DWORD dwBytesRead;
		if (!ReadFile(hModule, Buffer, GetFileSize(hModule, NULL), &dwBytesRead, NULL))
			printf("Failed to read file Error %d\n", GetLastError());
	}

	~CFindPatternEx() {
		VirtualFree(Buffer, NULL, MEM_RELEASE);
	}

	bool FindPatternEx(std::string szPattern) {
		return FindPatternSimplified((DWORD)Buffer, GetFileSize(hModule, NULL), szPattern.c_str());
	}
};

