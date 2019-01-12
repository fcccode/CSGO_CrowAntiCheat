#pragma once
#include "stdafx.h"
//É¾³ýÊý×é
#define SafeDeleteArraySize(pData) { if(pData){delete []pData;pData=NULL;} }
#pragma comment(lib, "Wintrust.lib") 
#pragma comment(lib, "crypt32.lib")
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
struct ThreadParms
{
	CString FileDirectory;
	int ScanType;
	DWORD PID;
};
class MyTools {
public:

	//void SendMd52Server(CString FileDirectory);

	void CheckFileIsCheat(CString FileDirectory, int ScanType,DWORD PID);

	BOOL static GetFileMd5(CString FileDirectory, CString & strFileMd5);
	BOOL DisableWow64FsRedirection(void);

	BOOL RevertWow64FsRedirection(void);

	BOOL RedirectionCreateFile(const wchar_t * pFilePath, HANDLE & hFile);

	wchar_t * GetCertName(wchar_t * pFilePath);

	wchar_t * GetFileCat(wchar_t * lpFileName);

	wchar_t * GetFileCertNameA(wchar_t * pFilePath);

	BOOL CheckFileTrust(wchar_t * lpFileName);
	std::string PID2FilePatch(DWORD process_id);
};