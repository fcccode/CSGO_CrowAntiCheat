#pragma once
#include "stdafx.h"
typedef enum _MSGTYPE {
	ENUM_MSG_DLL = 0, //DLL消息
	ENUM_MSG_HADLE_PROCESS, //被进程打开消息
	ENUM_MSG_HADLE_THREAD, //线程启动的消息
	ENUM_MSG_LOADIMAGE //模块加载的消息
} MSGTYPE;
typedef enum _NPMINI_COMMAND {
	ENUM_PASS = 0,
	ENUM_BLOCK
} NPMINI_COMMAND;
/****************************************************************************************/
typedef struct _COMMAND_MESSAGE {
	MSGTYPE MSG_TYPE;
	NPMINI_COMMAND  Command;
	WCHAR Contents[1024];
	ULONG Pid;
} COMMAND_MESSAGE, *PCOMMAND_MESSAGE;
typedef struct _USERCOMMAND_MESSAGE {

	FILTER_MESSAGE_HEADER MessageHeader;
	COMMAND_MESSAGE Notification;
	OVERLAPPED Ovlp;

} USERCOMMAND_MESSAGE, *PUSERCOMMAND_MESSAGE;
typedef struct _USERCOMMAND_MESSAGE_REPLAY
{
	FILTER_REPLY_HEADER  replayHeader;
	COMMAND_MESSAGE cmdMessage;
}USERCOMMAND_MESSAGE_REPLAY, *PUSERCOMMAND_MESSAGE_REPLAY;

typedef struct _MiniFilterPort {
	int Port;
	WCHAR Password[1024];
} NMiniFilterPort, *NMINIFILTERPORT;

class DriverConnecter {
public:
	void AntiCheatDriverCallbacks();

};