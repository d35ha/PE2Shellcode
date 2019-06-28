#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#ifdef __GNUC__
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif

#define GET_DIRECTORY_ENTRY(lpNtHeader, dwEntry) lpNtHeader->OptionalHeader.DataDirectory[dwEntry].VirtualAddress
#define GET_DIRECTORY_SIZE(lpNtHeader, dwEntry) lpNtHeader->OptionalHeader.DataDirectory[dwEntry].Size

LPCSTR GetNtStatusFormat(NTSTATUS ntCode);
LPCSTR GetLastErrorFormat(ULONG dwErrorCode = -1);
BOOL printf_error(LPCSTR _Format, ...);
BOOL printf_info(LPCSTR _Format, ...);
BOOL printf_success(LPCSTR _Format, ...);
BOOL ReportBadPE(LPCSTR lpErrorStr);
BOOL ReportApiError(LPCSTR szApiName, LPCSTR szMsg);
BOOL ReportNtStastus(LPCSTR szApiName, NTSTATUS NtCode, LPCSTR szMsg);