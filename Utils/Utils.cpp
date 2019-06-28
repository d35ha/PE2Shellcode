#include "Utils.h"

#pragma comment (lib, "ntdll.lib")

#define CONSOLE_COLOR_GREEN		0xA
#define CONSOLE_COLOR_YELLOW	0xE
#define CONSOLE_COLOR_RED		0xC
#define CONSOLE_COLOR_WHITE		0x7

HANDLE hConsole = NULL;
CHAR ErrorMsg[MAX_PATH] = { 0 };

BOOL printf_success(LPCSTR _Format, ...)
{
	if (!hConsole) hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	va_list ArgList = NULL;
	va_start(ArgList, _Format);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_GREEN);
	printf("[+] ");
	vprintf(_Format, ArgList);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_WHITE);
	va_end(ArgList);
	return TRUE;
};

BOOL printf_info(LPCSTR _Format, ...)
{
	if (!hConsole) hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	va_list ArgList = NULL;
	va_start(ArgList, _Format);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_YELLOW);
	printf("[!] ");
	vprintf(_Format, ArgList);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_WHITE);
	va_end(ArgList);
	return TRUE;
};

BOOL printf_error(LPCSTR _Format, ...)
{
	if (!hConsole) hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	va_list ArgList = NULL;
	va_start(ArgList, _Format);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_RED);
	printf("[-] ");
	vprintf(_Format, ArgList);
	SetConsoleTextAttribute(hConsole, CONSOLE_COLOR_WHITE);
	va_end(ArgList);
	return TRUE;
};

LPCSTR GetLastErrorFormat(ULONG dwErrorCode)
{
	if (dwErrorCode == -1) dwErrorCode = GetLastError();
	if (!FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErrorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		ErrorMsg,
		sizeof(ErrorMsg),
		NULL))
	{
		printf_error("Error at getting the last error format of code 0x%lx\n", dwErrorCode);
		sprintf_s(ErrorMsg, "0x%lx", dwErrorCode);
	};
	return ErrorMsg;
};

LPCSTR GetNtStatusFormat(NTSTATUS ntCode)
{
	ULONG dwErrorCode = RtlNtStatusToDosError(ntCode);
	if (dwErrorCode == ERROR_MR_MID_NOT_FOUND)
	{
		printf_error("Error at getting the error code of ntstatus 0x%lx\n", ntCode);
		sprintf_s(ErrorMsg, "0x%lx", dwErrorCode);
		return ErrorMsg;
	};
	return GetLastErrorFormat(dwErrorCode);
};

BOOL ReportBadPE(LPCSTR lpErrorStr)
{
	printf_error("Invalid or unsupported PE file, %s\n", lpErrorStr);
	return TRUE;
};

BOOL ReportApiError(LPCSTR szApiName, LPCSTR szMsg)
{
	printf_error("Error at %s, %s, error code/msg = %s\n", szApiName, szMsg, GetLastErrorFormat(GetLastError()));
	return TRUE;
};

BOOL ReportNtStastus(LPCSTR szApiName, NTSTATUS NtCode, LPCSTR szMsg)
{
	printf_error("Error at %s, %s, status code/msg = %s\n", szApiName, szMsg, GetNtStatusFormat(NtCode));
	return TRUE;
};