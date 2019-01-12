// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once
//#define _AFXDLL
#define  _CRT_SECURE_NO_WARNINGS 
#include "targetver.h"

#include <stdio.h>
#include <tchar.h>

// TODO:  在此处引用程序需要的其他头文件
#include <afx.h>
#include <winsvc.h>
#include <winioctl.h>
#include <stdio.h>

#include <stdlib.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>

#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#include <wchar.h>
#include<winnt.h>
#include <string>
#include <Wincrypt.h>
#include <Psapi.h>
#include"tlhelp32.h"
#pragma comment(lib, "wintrust")
#define DRIVER_NAME "test"
#define DRIVER_PATH ".\\test.sys"
#define	DRIVER_ALTITUDE	"370030"
#define IOCTL_START	0x80001
#define IOCTL_GET_DATA 0x80002
typedef enum _SCANCHEAT_TYPE {
	SCANTYPE_FAST = 0, //只检查MD5
	SCANTYPE_HIIGHT //检查md5 + 扫描模块 + 手工加载模块 + 启发式扫描(上传服务端)
} NSCANCHEAT_TYPE;
