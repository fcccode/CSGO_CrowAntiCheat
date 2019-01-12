#pragma once
#include "stdafx.h"
class DriverInstall {
public:

	BOOL InstallDriver(const char * lpszDriverName, const char * lpszDriverPath, const char * lpszAltitude);

	BOOL StartDriver(const char * lpszDriverName);

	BOOL StopDriver(const char * lpszDriverName);

	BOOL DeleteDriver(const char * lpszDriverName);

};