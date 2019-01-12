// minifilter驱动安装.cpp : 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include "DriverInstall.h"
#include "DriverConnecter.h"

DriverInstall DriverInstaller;
DriverConnecter Driver;
void AntiCheatDriverIInstall()
{
	if (DriverInstaller.InstallDriver(DRIVER_NAME, DRIVER_PATH, DRIVER_ALTITUDE))
		printf("Install Driver Success \n");
	else
		printf("Install Driver Fail %d \n", GetLastError());
	if (DriverInstaller.StartDriver(DRIVER_NAME))
	{
		Driver.AntiCheatDriverCallbacks();
		printf("Start Driver Success \n");
	}
	else
		printf("Start Driver Fail %d \n", GetLastError());
	while (true)
	{
		;
	}
	//要写一个bug report程序
	DriverInstaller.StopDriver(DRIVER_NAME);
	DriverInstaller.DeleteDriver(DRIVER_NAME);
}
int main(void)
{
	/*
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, 11180);
	MEMORY_BASIC_INFORMATION mbi_thunk;
	PVOID AllocationBase = NULL;
	TCHAR FilePath[MAX_PATH];
	for (LPSTR Addr = (LPSTR)0x00000000; ::VirtualQueryEx(hProcess, Addr, &mbi_thunk, sizeof(mbi_thunk)); Addr = LPSTR(mbi_thunk.BaseAddress) + mbi_thunk.RegionSize)
	{
		if ((mbi_thunk.AllocationBase > AllocationBase) && (GetMappedFileName(hProcess, mbi_thunk.BaseAddress, FilePath, _countof(FilePath)) > 0))
		{
			AllocationBase = mbi_thunk.AllocationBase;
			printf("MODULE:%x, %s \n", AllocationBase, FilePath);
		}
	}*/

	//PEreverser.GetFileLevel("C:\\Users\\Administrator\\Desktop\\RainbowSix.vmp.exe",false);
	//CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)AntiCheatDriverIInstall, NULL, NULL, NULL);
	AntiCheatDriverIInstall();
	/*
	要做的事情:
	1. 代码错误控制模块 *
	2. 窗口覆盖检查 *
	3. CSGO注入反作弊模块 *
	4. 下载服务端的白名单数字签名列表 *
	5. 机器码封锁 *
	6. 捕获mouse_event等鼠标模拟 事件 *
	7. 窗口截图 *
	8. DNSCACHE、驱动、USN扫描 *
	9. Steam账号历史记录
	dll要做的:
	1. 检查VMT表是否正常 *
	2. 隐藏D3D接口 *
	3. 隐藏主要模块接口 *
	4. 游戏D3D窗口截图 *
	驱动要做的:
	1. MmUnloadedDriver扫描 *
	2. 剥离csrss.exe 、 lsass.exe的句柄 *
	*/
	system("pause");

	return 0;
}
