#include "stdafx.h"
#include "DriverConnecter.h"
#include "Tools.h"
MyTools* Tools = new MyTools;
typedef HRESULT
(WINAPI
	*FilterGetMessageT)(
		_In_ HANDLE hPort,
		_Out_writes_bytes_(dwMessageBufferSize) PFILTER_MESSAGE_HEADER lpMessageBuffer,
		_In_ DWORD dwMessageBufferSize,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
		);
typedef HRESULT
(WINAPI
	*FilterConnectCommunicationPortT)(
		_In_ LPCWSTR lpPortName,
		_In_ DWORD dwOptions,
		_In_reads_bytes_opt_(wSizeOfContext) LPCVOID lpContext,
		_In_ WORD wSizeOfContext,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_Outptr_ HANDLE *hPort
		);
typedef HRESULT
(WINAPI
	*FilterReplyMessageT)(
		_In_ HANDLE hPort,
		_In_reads_bytes_(dwReplyBufferSize) PFILTER_REPLY_HEADER lpReplyBuffer,
		_In_ DWORD dwReplyBufferSize
		);
FilterGetMessageT pFilterGetMessage = (FilterGetMessageT)GetProcAddress(LoadLibrary("FltLib.dll"), "FilterGetMessage");
FilterConnectCommunicationPortT pFilterConnectCommunicationPort = (FilterConnectCommunicationPortT)GetProcAddress(LoadLibrary("FltLib.dll"), "FilterConnectCommunicationPort");
FilterReplyMessageT pFilterReplyMessage = (FilterReplyMessageT)GetProcAddress(LoadLibrary("FltLib.dll"), "FilterReplyMessage");
void shit2()
{
	HANDLE port;
	DWORD dwRet;
	NMiniFilterPort PARM;
	PARM.Port = 1;
	HRESULT hr = pFilterConnectCommunicationPort(L"\\CrowACommunicationPort", 1, &PARM, sizeof(NMINIFILTERPORT), NULL, &port);
	if (IS_ERROR(hr))
	{
		printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
		getchar();
		return;
	}
	HANDLE completion = CreateIoCompletionPort(port, NULL, 0, 2024);
	if (completion == NULL) {
		printf("ERROR: Creating completion port: %d\n", GetLastError());
		CloseHandle(port);
		return;
	}
	printf("Port = 0x%p Completion = 0x%p\n", port, completion);
	USERCOMMAND_MESSAGE data;
	USERCOMMAND_MESSAGE_REPLAY dataReplay;
	while (TRUE)
	{
		LPOVERLAPPED lpOverlapped = NULL;
		HRESULT hr = pFilterGetMessage(port, (PFILTER_MESSAGE_HEADER)&data, sizeof(USERCOMMAND_MESSAGE), lpOverlapped);
		
		if (hr == S_OK)
		{
			if (data.Notification.MSG_TYPE == ENUM_MSG_LOADIMAGE)
			{
			//	printf("data.Notification : %ws \n", data.Notification.Contents);
				
				dataReplay.replayHeader.MessageId = data.MessageHeader.MessageId;
				hr = pFilterReplyMessage(port, (PFILTER_REPLY_HEADER)&dataReplay, sizeof(COMMAND_MESSAGE) + sizeof(FILTER_REPLY_HEADER));
				if (IS_ERROR(hr)) {
					printf("FilterGetMessage fail!\n");
				}
			//	Tools->CheckFileIsCheat(data.Notification.Contents, SCANTYPE_FAST, data.Notification.Pid);
			}
		}
	}
}
void DriverConnecter::AntiCheatDriverCallbacks()
{
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)shit2, NULL, NULL, NULL);
	HANDLE port;
	DWORD dwRet;
	NMiniFilterPort PARM;
	PARM.Port = 0;
	HRESULT hr = pFilterConnectCommunicationPort(L"\\CrowACommunicationPort", 0, &PARM, sizeof(NMINIFILTERPORT), NULL, &port);
	if (IS_ERROR(hr))
	{
		printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
		getchar();
		return;
	}
	HANDLE completion = CreateIoCompletionPort(port, NULL, 0, 2024);
	if (completion == NULL) {
		printf("ERROR: Creating completion port: %d\n", GetLastError());
		CloseHandle(port);
		return;
	}
	printf("Port = 0x%p Completion = 0x%p\n", port, completion);
	USERCOMMAND_MESSAGE data;
	USERCOMMAND_MESSAGE_REPLAY dataReplay;
	while (TRUE)
	{
		HRESULT hr = pFilterGetMessage(port, (PFILTER_MESSAGE_HEADER)&data, sizeof(USERCOMMAND_MESSAGE), NULL);
		if (hr == S_OK)
		{
			switch (data.Notification.MSG_TYPE)
			{
			case ENUM_MSG_DLL:
			{
				printf("DLL : %ws \n", data.Notification.Contents);
				if(Tools->CheckFileTrust(data.Notification.Contents))
					dataReplay.cmdMessage.Command = ENUM_PASS;
				else
				{
					printf("Block DLL : %ws \n", data.Notification.Contents);
					dataReplay.cmdMessage.Command = ENUM_BLOCK;
					//不是我们的白名单中的签名加入到了游戏进程中.上传到服务器.
					//..
				}
				
				Tools->CheckFileIsCheat(data.Notification.Contents, SCANTYPE_FAST, data.Notification.Pid);
			}break;
			case ENUM_MSG_HADLE_PROCESS:
			{
				//ENUM_MSG_HADLE_PROCESS = 常规打开进程操作
				std::string FilePatch = Tools->PID2FilePatch(data.Notification.Pid);
				if (FilePatch != std::string())
					Tools->CheckFileIsCheat(data.Notification.Contents, SCANTYPE_HIIGHT, data.Notification.Pid);
				else
					printf("FilePatch is null , what ? \n");

			}break;
			case ENUM_MSG_HADLE_THREAD:
			{
				
				std::string FilePatch = Tools->PID2FilePatch(data.Notification.Pid);
				if (FilePatch != std::string())
					Tools->CheckFileIsCheat(data.Notification.Contents, SCANTYPE_HIIGHT, data.Notification.Pid);
				else
					printf("FilePatch is null , what ? \n");

				//这个thread最高权限访问操作 来自于某个进程 有点可疑 为什么不上传到我们的服务器上呢?
				// ...
			}break;
			default:
				printf("Unknown MSG_TYPE :%d \n", data.Notification.MSG_TYPE);
				break;
			}
			dataReplay.replayHeader.MessageId = data.MessageHeader.MessageId;
			hr = pFilterReplyMessage(port, (PFILTER_REPLY_HEADER)&dataReplay, sizeof(COMMAND_MESSAGE) + sizeof(FILTER_REPLY_HEADER));
			if (IS_ERROR(hr)) {
				printf("FilterGetMessage fail!\n");
			}
			
		}
	}
}