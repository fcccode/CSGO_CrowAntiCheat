#include "Head.h"
int Sending = 0;
/** 向前声明 */
NTKERNELAPI
UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);
NTSTATUS ConnectNotifyCallback(IN PFLT_PORT ClientPort, IN PVOID ServerPortCookie, IN PVOID ConnectionContext, IN ULONG SizeOfContext, OUT PVOID * ConnectionPortCookie)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);

	NMINIFILTERPORT PARM = ConnectionContext;
	//DbgPrintEx(0, 0, "ClientPort %d \n", PARM->Port);
	if (PARM->Port == 0)
		g_ClientPort_DLL = ClientPort;
	else if (PARM->Port == 1)
		g_ClientPort_IMAGE = ClientPort;
	return STATUS_SUCCESS;
}
VOID DisconnectNotifyCallback(_In_opt_ PVOID ConnectionCookie)
{
	PAGED_CODE();
	UNREFERENCED_PARAMETER(ConnectionCookie);
	FltCloseClientPort(Filter, &g_ClientPort_DLL);
	FltCloseClientPort(Filter, &g_ClientPort_IMAGE);
}

//我们要搞得IRP回调,拦截CreateFileMapping/CreateSection
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{
	IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
	PreCreateSection,
	NULL
	},
	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),				// Size
	FLT_REGISTRATION_VERSION,				// Version
	0,										// Flags
	NULL,									// ContextRegistration
	Callbacks,								// OperationRegistration
	Unload,									// FilterUnloadCallback
	NULL,									// InstanceSetupCallback
	NULL,									// InstanceQueryTeardownCallback
	NULL,									// InstanceTeardownStartCallback
	NULL,									// InstanceTeardownCompleteCallback
	NULL,									// GenerateFileNameCallback
	NULL,									// NormalizeNameComponentCallback
	NULL									// NormalizeContextCleanupCallback
};

/*
其实一些风骚的pe文件的e_lfanew可能大于0x1000，比如某文件的e_lfanew是0x30000
于是只读0x1000的判断pe就统统升天
有大于0x1000自然有还有小于0的e_lfanew（dosheader里这玩意是LONG）
*/
BOOL IsValidImage(PFLT_INSTANCE Instance, PFILE_OBJECT FileObject)
{
	PVOID FileBuffer = ExAllocatePool(PagedPool, 0x4000);
	if (FileBuffer)
	{
		LARGE_INTEGER offset = { 0 };
		ULONG BufferSize = 0;
		NTSTATUS st = FltReadFile(Instance, FileObject, &offset, 0x4000, FileBuffer,FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, &BufferSize, NULL, NULL);
		if (NT_SUCCESS(st))
		{
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
			//读e_magic也就是MZ
			if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}
//输入\\??\\c:-->\\device\\\harddiskvolume1
//LinkTarget.Buffer注意要释放

NTSTATUS QuerySymbolicLink(
	IN PUNICODE_STRING SymbolicLinkName,
	OUT PUNICODE_STRING LinkTarget
)
{
	OBJECT_ATTRIBUTES   oa = { 0 };
	NTSTATUS            status = 0;
	HANDLE              handle = NULL;

	InitializeObjectAttributes(
		&oa,
		SymbolicLinkName,
		OBJ_CASE_INSENSITIVE,
		0,
		0);

	status = ZwOpenSymbolicLinkObject(&handle, GENERIC_READ, &oa);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	LinkTarget->MaximumLength = MAX_PATH * sizeof(WCHAR);
	LinkTarget->Length = 0;
	LinkTarget->Buffer = ExAllocatePoolWithTag(PagedPool, LinkTarget->MaximumLength, 'SOD');
	if (!LinkTarget->Buffer)
	{
		ZwClose(handle);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(LinkTarget->Buffer, LinkTarget->MaximumLength);

	status = ZwQuerySymbolicLinkObject(handle, LinkTarget, NULL);
	ZwClose(handle);

	if (!NT_SUCCESS(status))
	{
		ExFreePool(LinkTarget->Buffer);
	}

	return status;
}

//输入\\Device\\harddiskvolume1
//输出C:
//DosName.Buffer的内存记得释放

NTSTATUS
MyRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING DeviceName,
	OUT PUNICODE_STRING DosName
)
{
	NTSTATUS                status = 0;
	UNICODE_STRING          driveLetterName = { 0 };
	WCHAR                   driveLetterNameBuf[128] = { 0 };
	WCHAR                   c = L'\0';
	WCHAR                   DriLetter[3] = { 0 };
	UNICODE_STRING          linkTarget = { 0 };

	for (c = L'A'; c <= L'Z'; c++)
	{
		RtlInitEmptyUnicodeString(&driveLetterName, driveLetterNameBuf, sizeof(driveLetterNameBuf));
		RtlAppendUnicodeToString(&driveLetterName, L"\\??\\");
		DriLetter[0] = c;
		DriLetter[1] = L':';
		DriLetter[2] = 0;
		RtlAppendUnicodeToString(&driveLetterName, DriLetter);

		status = QuerySymbolicLink(&driveLetterName, &linkTarget);
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		if (RtlEqualUnicodeString(&linkTarget, DeviceName, TRUE))
		{
			ExFreePool(linkTarget.Buffer);
			break;
		}

		ExFreePool(linkTarget.Buffer);
	}

	if (c <= L'Z')
	{
		DosName->Buffer = ExAllocatePoolWithTag(PagedPool, 3 * sizeof(WCHAR), 'SOD');
		if (!DosName->Buffer)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		DosName->MaximumLength = 6;
		DosName->Length = 4;
		*DosName->Buffer = c;
		*(DosName->Buffer + 1) = ':';
		*(DosName->Buffer + 2) = 0;

		return STATUS_SUCCESS;
	}

	return status;
}

//c:\\windows\\hi.txt<--\\device\\harddiskvolume1\\windows\\hi.txt
BOOL NTAPI GetNTLinkName(WCHAR *wszNTName, WCHAR *wszFileName)
{
	UNICODE_STRING      ustrFileName = { 0 };
	UNICODE_STRING      ustrDosName = { 0 };
	UNICODE_STRING      ustrDeviceName = { 0 };

	WCHAR               *pPath = NULL;
	ULONG               i = 0;
	ULONG               ulSepNum = 0;


	if (wszFileName == NULL ||
		wszNTName == NULL ||
		_wcsnicmp(wszNTName, L"\\device\\harddiskvolume", wcslen(L"\\device\\harddiskvolume")) != 0)
	{
		return FALSE;
	}

	ustrFileName.Buffer = wszFileName;
	ustrFileName.Length = 0;
	ustrFileName.MaximumLength = sizeof(WCHAR)*MAX_PATH;

	while (wszNTName[i] != L'\0')
	{

		if (wszNTName[i] == L'\0')
		{
			break;
		}
		if (wszNTName[i] == L'\\')
		{
			ulSepNum++;
		}
		if (ulSepNum == 3)
		{
			wszNTName[i] = UNICODE_NULL;
			pPath = &wszNTName[i + 1];
			break;
		}
		i++;
	}

	if (pPath == NULL)
	{
		return FALSE;
	}

	RtlInitUnicodeString(&ustrDeviceName, wszNTName);

	if (!NT_SUCCESS(MyRtlVolumeDeviceToDosName(&ustrDeviceName, &ustrDosName)))
	{
		return FALSE;
	}

	RtlCopyUnicodeString(&ustrFileName, &ustrDosName);
	RtlAppendUnicodeToString(&ustrFileName, L"\\");
	RtlAppendUnicodeToString(&ustrFileName, pPath);

	ExFreePool(ustrDosName.Buffer);

	return TRUE;
}

BOOL QueryVolumeName(WCHAR ch, WCHAR * name, USHORT size)
{
	WCHAR szVolume[7] = L"\\??\\C:";
	UNICODE_STRING LinkName;
	UNICODE_STRING VolName;
	UNICODE_STRING ustrTarget;
	NTSTATUS ntStatus = 0;

	RtlInitUnicodeString(&LinkName, szVolume);

	szVolume[4] = ch;

	ustrTarget.Buffer = name;
	ustrTarget.Length = 0;
	ustrTarget.MaximumLength = size;

	ntStatus = QuerySymbolicLink(&LinkName, &VolName);
	if (NT_SUCCESS(ntStatus))
	{
		RtlCopyUnicodeString(&ustrTarget, &VolName);
		ExFreePool(VolName.Buffer);
	}
	return NT_SUCCESS(ntStatus);

}

//\\??\\c:\\windows\\hi.txt-->\\device\\harddiskvolume1\\windows\\hi.txt

BOOL NTAPI GetNtDeviceName(WCHAR * filename, WCHAR * ntname)
{
	UNICODE_STRING uVolName = { 0,0,0 };
	WCHAR volName[MAX_PATH] = L"";
	WCHAR tmpName[MAX_PATH] = L"";
	WCHAR chVol = L'\0';
	WCHAR * pPath = NULL;
	int i = 0;
	
	RtlStringCbCopyW(tmpName, MAX_PATH * sizeof(WCHAR), filename);
	for (i = 1; i < MAX_PATH - 1; i++)
	{
		if (tmpName[i] == L':')
		{
			pPath = &tmpName[(i + 1) % MAX_PATH];
			chVol = tmpName[i - 1];
			break;
		}
	}

	if (pPath == NULL)
	{
		return FALSE;
	}

	if (chVol == L'?')
	{
		uVolName.Length = 0;
		uVolName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uVolName.Buffer = ntname;
		RtlAppendUnicodeToString(&uVolName, L"\\Device\\HarddiskVolume?");
		RtlAppendUnicodeToString(&uVolName, pPath);
		return TRUE;
	}
	else if (QueryVolumeName(chVol, volName, MAX_PATH * sizeof(WCHAR)))
	{
		uVolName.Length = 0;
		uVolName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		uVolName.Buffer = ntname;
		RtlAppendUnicodeToString(&uVolName, volName);
		RtlAppendUnicodeToString(&uVolName, pPath);
		return TRUE;
	}

	return FALSE;
}
FLT_PREOP_CALLBACK_STATUS PreCreateSection(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID *CompletionContext) {
	FLT_PREOP_CALLBACK_STATUS ret = FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection) {
		PFLT_FILE_NAME_INFORMATION pNameInfo = NULL;
		if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pNameInfo))) {
			if (IsValidImage(FltObjects->Instance, FltObjects->FileObject)) {
				if (FltGetRequestorProcessId(Data) == GamePid) {
					PCOMMAND_MESSAGE notification = NULL;
					COMMAND_MESSAGE reply;
					notification = ExAllocatePoolWithTag(NonPagedPool,
						sizeof(COMMAND_MESSAGE),
						'nacS');
					GetNTLinkName(pNameInfo->Name.Buffer, notification->Contents);
					reply.MSG_TYPE = ENUM_MSG_DLL;
					notification->MSG_TYPE = ENUM_MSG_DLL;
					//DbgPrintEx(0, 0, "pNameInfo->Name.Buffer is %wZ\n", pNameInfo->Name);
					ULONG replyLength = sizeof(COMMAND_MESSAGE);
					NTSTATUS status = FltSendMessage(Filter, &g_ClientPort_DLL, notification, sizeof(COMMAND_MESSAGE), &reply, &replyLength, NULL);		
					if (NT_SUCCESS(status))
					{
						//DbgPrintEx(0, 0, "send succeed\n");
						//DbgPrintEx(0, 0, "path is %wZ\n", pNameInfo->Name);
						//DbgPrintEx(0, 0, "path is %S\n", notification->Contents);
						if (reply.Command == ENUM_PASS)
						{
							DbgPrintEx(0, 0, "\n Pass Dll: %wZ \n", pNameInfo->Name);
							return ret;
						}
						else if (reply.Command == ENUM_BLOCK)
						{
							//拦截加载
							DbgPrintEx(0, 0, "\n Minifilter : Block Image %wZ \n", pNameInfo->Name);
							Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;//←这样才能没有错误提示 // STATUS_ACCESS_DENIED;
							ret = FLT_PREOP_COMPLETE;
						}
					}
					else
					{
						Sending = 0;
						DbgPrintEx(0, 0, "send failed\n");
						Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
						ret = FLT_PREOP_COMPLETE;
					}
					return ret;

				}
				else
				{
					//对于其他的image 做一遍特征码扫描就行了
					PCOMMAND_MESSAGE notification = NULL;
					COMMAND_MESSAGE reply;
					notification = ExAllocatePoolWithTag(NonPagedPool,
						sizeof(COMMAND_MESSAGE),
						'nacS');
					GetNTLinkName(pNameInfo->Name.Buffer, notification->Contents);
					reply.MSG_TYPE = ENUM_MSG_LOADIMAGE;
					notification->MSG_TYPE = ENUM_MSG_LOADIMAGE;
					notification->Pid = FltGetRequestorProcessId(Data);
					ULONG replyLength = sizeof(COMMAND_MESSAGE);
					FltSendMessage(Filter, &g_ClientPort_IMAGE, notification, sizeof(COMMAND_MESSAGE), &reply, &replyLength, NULL);
					return FLT_PREOP_SUCCESS_NO_CALLBACK;
				}
					
			}
		}
	}
	return ret;
}

//发挥你的想象力
VOID CreateThreadNotifyRoutine(IN HANDLE hParentId, IN HANDLE hProcessId, IN BOOLEAN bCreate)
{
	;
}
VOID CreateProcessNotifyRoutine(IN HANDLE hParentId,IN HANDLE hProcessId,IN BOOLEAN bCreate)
{
	;
}
//用于记录DLL和驱动加载
VOID LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessID, IN PIMAGE_INFO ImageInfo)
{
	;
//	DbgPrintEx(0, 0, "Loaded Modules. ProcessID = %d, ThreadID = %d, Full ImageInfo = %d \n", ProcessID, ProcessID, ImageInfo);
	//如果是CSGO的进程一定有client.dll 所以是 if (wcsstr(FullImageName->Buffer, L"\\csgo\\bin\\client.dll")) 以及判断数字签名
	//直接从这里得到游戏ID只是临时测试用的,一定要一个R3的客户端去启动CSGO防止有些挂通过父进程得到句柄权限.
	
	if (wcsstr(FullImageName->Buffer, L"\\csgo.exe")) {
		GamePid = ProcessID;
		DbgPrintEx(0, 0, "Found Game PID! \n");
	}
	if (ProcessID == GamePid)
	{
	}
	
	//稍微检查一下是否有外挂模块注入到其他的进程里,不用了,垃圾玩意
	
}
//句柄创建后我们要干什么呢? :)
VOID HandleAfterCreat(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
}
//线程创建检查,可以回溯到是谁是谁创建的,目标进程是谁
OB_PREOP_CALLBACK_STATUS ThreadHandleCallbacks(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if (GamePid == -1)
		return OB_PREOP_SUCCESS;
	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;
	if ((ULONG)PsGetCurrentProcessId() == GamePid)
		return OB_PREOP_SUCCESS;
	
	if (PsGetThreadProcessId(OperationInformation->Object) == GamePid)
	{
		//这里必须要检查是不是CSGO内部的client.dll这些东西的线程要不然会CRASH的
		//DbgPrintEx(0, 0, "ThreadHandleCallbacks! from pid: %d \n", PsGetCurrentProcessId());
		PCOMMAND_MESSAGE notification = NULL;
		COMMAND_MESSAGE reply;
		//notification = ExAllocatePoolWithTag(NonPagedPool,sizeof(COMMAND_MESSAGE),'nacS');
		//	GetNTLinkName(pNameInfo->Name.Buffer, notification->Contents);
		//reply.MSG_TYPE = ENUM_MSG_HADLE_THREAD;
		//notification->MSG_TYPE = ENUM_MSG_HADLE_THREAD;
		//notification->Pid = PsGetCurrentProcessId();
		//ULONG replyLength = sizeof(COMMAND_MESSAGE);
		//NTSTATUS status = 0;// FltSendMessage(Filter, &g_ClientPort, notification, sizeof(COMMAND_MESSAGE), &reply, &replyLength, NULL);
		//if (!NT_SUCCESS(status))
		//	DbgPrintEx(0, 0, "ThreadHandleCallbacks! ,Send MeG Fail PID: %d \n", PsGetCurrentProcessId());
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
		else
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
	}
	return OB_PREOP_SUCCESS;

}
OB_PREOP_CALLBACK_STATUS ProcessHandleCallbacks(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (GamePid == -1)
		return OB_PREOP_SUCCESS;
	//有点懒了必须要让那堆系统进程过,要不然会蓝屏
	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;
	if ((ULONG)PsGetCurrentProcessId() == GamePid)
		return OB_PREOP_SUCCESS;
	PEPROCESS ProtectedProcessPEPROCESS;
	PEPROCESS ProtectedUserModeACPEPROCESS;

	PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object,
		CurrentProcess = PsGetCurrentProcess();

	ULONG ulProcessId = PsGetProcessId(OpenedProcess);

	if (PsGetProcessId((PEPROCESS)OperationInformation->Object) == GamePid)
	{
		//DbgPrintEx(0, 0, "ProcessHandleCallbacks! ,PID: %s \n", PsGetProcessImageFileName(PsGetCurrentProcess()));
			
		PCOMMAND_MESSAGE notification = NULL;
		COMMAND_MESSAGE reply;
	//	notification = ExAllocatePoolWithTag(NonPagedPool,sizeof(COMMAND_MESSAGE),'nacS');
	//	GetNTLinkName(pNameInfo->Name.Buffer, notification->Contents);
	//	reply.MSG_TYPE = ENUM_MSG_HADLE_PROCESS;
	//	notification->MSG_TYPE = ENUM_MSG_HADLE_PROCESS;
	//	notification->Pid = PsGetCurrentProcessId();
	//	ULONG replyLength = sizeof(COMMAND_MESSAGE);
	//	NTSTATUS status = FltSendMessage(Filter, &g_ClientPort, notification, sizeof(COMMAND_MESSAGE), &reply, &replyLength, NULL);
	//	if (!NT_SUCCESS(status))
	//		DbgPrintEx(0, 0, "ProcessHandleCallbacks! ,Send MeG Fail PID: %d \n", PsGetCurrentProcessId());
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) // striping handle 
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE);
		}
		else
		{
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE);
		}
	}
	return OB_PREOP_SUCCESS;
}
//装上callbacks
VOID InstallCallBacks()
{

	NTSTATUS NtHandleCallback = STATUS_UNSUCCESSFUL;
	NTSTATUS NtThreadCallback = STATUS_UNSUCCESSFUL;

	OB_OPERATION_REGISTRATION OBOperationRegistration[2];
	OB_CALLBACK_REGISTRATION OBOCallbackRegistration;
	REG_CONTEXT regContext;
	UNICODE_STRING usAltitude;
	memset(&OBOperationRegistration, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&OBOCallbackRegistration, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&regContext, 0, sizeof(REG_CONTEXT));
	regContext.ulIndex = 1;
	regContext.Version = 120;
	RtlInitUnicodeString(&usAltitude, L"1000");	
	if ((USHORT)ObGetFilterVersion() == OB_FLT_REGISTRATION_VERSION)
	{
		OBOperationRegistration[1].ObjectType = PsProcessType;
		OBOperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		OBOperationRegistration[1].PreOperation = ProcessHandleCallbacks;
		OBOperationRegistration[1].PostOperation = HandleAfterCreat;
		OBOperationRegistration[0].ObjectType = PsThreadType;
		OBOperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		OBOperationRegistration[0].PreOperation = ThreadHandleCallbacks;
		OBOperationRegistration[0].PostOperation = HandleAfterCreat;
		OBOCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		OBOCallbackRegistration.OperationRegistrationCount = 2;
		OBOCallbackRegistration.RegistrationContext = &regContext;
		OBOCallbackRegistration.OperationRegistration = &OBOperationRegistration;
		NtHandleCallback = ObRegisterCallbacks(&OBOCallbackRegistration, &CallbacksHandle); // Register The CallBack
		PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
		PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
		//PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine,FALSE);
		if (!NT_SUCCESS(NtHandleCallback))
		{
			if (CallbacksHandle)
			{
				ObUnRegisterCallbacks(CallbacksHandle);
				CallbacksHandle = NULL;
			}
			DbgPrintEx(0, 0, "Failed to install ObRegisterCallbacks: <0x%08x>.\n", NtHandleCallback);
		}else
			DbgPrintEx(0, 0, "Success: ObRegisterCallbacks Was Be Install\n");
	}
}
/*
//驱动控制部分
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

	NTSTATUS status = STATUS_SUCCESS;

	ULONG ulReturn = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	//驱动控制代码
	ULONG ulCtrlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	//输入输出缓冲区
	PVOID InputBuffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;
	PVOID OutputBuffer = (PVOID)Irp->AssociatedIrp.SystemBuffer;

	//输入输出缓冲区大小
	ULONG ulInputBufferSize = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG ulOutputBufferSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
	switch (ulCtrlCode)
	{
	case IOCTL_START:
	{
		//设置同步事件
		if (InputBuffer == NULL || ulInputBufferSize < sizeof(HANDLE))
		{
			DbgPrintEx(0, 0, "Set Event Error~!\n");
			break;
		}
		//取得句柄对象
		HANDLE hEvent = *(HANDLE*)InputBuffer;
		status = ObReferenceObjectByHandle(hEvent, GENERIC_ALL, NULL, KernelMode, (PVOID*)&g_pEventObject, &g_ObjectHandleInfo);
		break;
	}
	default:
		break;
	}
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = ulOutputBufferSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}
*/
NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);
	DbgPrintEx(0, 0, "unload minifilter\n");
	FltUnregisterFilter(Filter);
	return STATUS_SUCCESS;
}
//这里如果为了防止被挂删除的,直接写蓝屏,我们的AC是不可能卸载驱动的
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrintEx(0, 0, "UNLOADED \n");
	//PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
	//PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
	if (CallbacksHandle)
		ObUnRegisterCallbacks(CallbacksHandle);
//	if (Filter)
//		FltUnregisterFilter(Filter);
	FltCloseCommunicationPort(g_ServerPort);
	UNICODE_STRING SACSymbolName;
	RtlInitUnicodeString(&SACSymbolName, L"\\DosDevices\\CrowAC"); // Giving the driver a symbol
	IoDeleteSymbolicLink(&SACSymbolName);
	IoDeleteDevice(pDriverObject->DeviceObject);
}
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrintEx(0, 0, "LOADED \n");
	UNICODE_STRING SACDriverName, SACSymbolName;
	OBJECT_ATTRIBUTES oa;
	PSECURITY_DESCRIPTOR sd = NULL;
	NTSTATUS NtRet = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObj;
	UNICODE_STRING uniString;
	RtlInitUnicodeString(&uniString, L"\\CrowACommunicationPort");
	RtlInitUnicodeString(&SACDriverName, L"\\Device\\CrowAC");
	RtlInitUnicodeString(&SACSymbolName, L"\\DosDevices\\CrowAC");
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;
	NTSTATUS NtRet2 = IoCreateDevice(pDriverObject, 0, &SACDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	IoCreateSymbolicLink(&SACSymbolName, &SACDriverName);
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =// IoControl;
	
	pDeviceObj->Flags |= DO_DIRECT_IO;
	pDeviceObj->Flags &= (~DO_DEVICE_INITIALIZING);
	pDriverObject->DriverUnload = DriverUnload;
	//这里做一些关于CSGO的校验判断是不是真的加载进CSGO里了
	//DbgPrintEx(0, 0, "Started Pid : %d \n", PsGetCurrentProcessId());
	//GamePid = PsGetCurrentProcessId();
	GamePid = -1;
	NTSTATUS status = FltRegisterFilter(pDriverObject, &FilterRegistration, &Filter);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "Failed to register filter: <0x%08x>.\n", status);
		return status;
	}
	FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	InitializeObjectAttributes(&oa, &uniString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
	FltCreateCommunicationPort(Filter, &g_ServerPort, &oa, NULL, ConnectNotifyCallback, DisconnectNotifyCallback, NULL, 2);
	FltFreeSecurityDescriptor(sd);
	status = FltStartFiltering(Filter);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "Failed to start filter: <0x%08x>.\n", status);
		FltUnregisterFilter(Filter);
		FltCloseCommunicationPort(g_ServerPort);
	}
	PLDR_DATA_TABLE_ENTRY64 ldr;
	// 绕过MmVerifyCallbackFunction。
	ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObject->DriverSection;
	ldr->Flags |= 0x20;
	InstallCallBacks();
	DbgPrintEx(0, 0, "Success Install Driver \n");
	return status;
}