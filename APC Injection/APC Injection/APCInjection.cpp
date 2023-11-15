#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>

#define NT_SUCCESS(status) (status >= 0)
#pragma comment(lib, "ntdll")
extern "C" NTSTATUS __stdcall NtSuspendThread(HANDLE ThreadHandle, PULONG SuspendCount);
extern "C" NTSTATUS __stdcall NtAlertResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

int wmain(int argc, const wchar_t* argv[])
{
	if (argc < 2)
	{
		wprintf(L"wmain: Usage: %s [pid]\n", argv[0]);
		return 0;
	}

	DWORD dwPid{ static_cast<DWORD>(_wtoi(argv[1])) };
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _wtoi(argv[1]));
	if (hProcess == nullptr)
	{
		wprintf(L"wmain: OpenProcess() error. (%d)\n", GetLastError());
		return 0;
	}

	std::wstring strPath(MAX_PATH, 0);
	if (!GetModuleFileName(nullptr, (WCHAR*)strPath.data(), 256))
	{
		wprintf(L"wmain: GetModuleFileName() error. (%d)\n", GetLastError());
		return 0;
	}
	strPath = strPath.substr(0, strPath.rfind('\\'));
	strPath += L"\\Message.dll";

	LPVOID memPtr = VirtualAllocEx(hProcess, nullptr, strPath.length() * sizeof(WCHAR) + 1, MEM_COMMIT, PAGE_READWRITE);
	if (memPtr == nullptr)
	{
		wprintf(L"wmain: VirtualAllocEx() error. (%d)\n", GetLastError());
		return 0;
	}

	if (!WriteProcessMemory(hProcess, memPtr, strPath.c_str(), strPath.length() * sizeof(WCHAR), nullptr))
	{
		wprintf(L"wmain: WriteProcessMemory() error. (%d)\n", GetLastError());
		return 0;
	}

	HANDLE hSnapshot{ CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		wprintf(L"wmain: CreateToolHelp32Snapshot() error. (%d)\n", GetLastError());
		return 0;
	}

	std::vector<DWORD> arrThreads;
	THREADENTRY32 te{ 0, };
	te.dwSize = sizeof(te);

	Thread32First(hSnapshot, &te);
	do
	{
		if (dwPid == te.th32OwnerProcessID)
		{
			arrThreads.push_back(te.th32ThreadID);
			wprintf(L"wmain: threadId: %d\n", te.th32ThreadID);
		}
	} while (Thread32Next(hSnapshot, &te));
	if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != nullptr) CloseHandle(hSnapshot);
	hSnapshot = nullptr;

	for (const auto& threadId : arrThreads)
	{
		HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
		if (hThread == nullptr)
			continue;

		do
		{
			if (!NT_SUCCESS(NtSuspendThread(hThread, nullptr)))
			{
				wprintf(L"wmain: NtSuspendThread() error.\n");
			}

			if (!QueueUserAPC((PAPCFUNC)LoadLibraryW, hThread, reinterpret_cast<ULONG_PTR>(memPtr)))
			{
				wprintf(L"QueueUserAPC() error. (%d)\n", GetLastError());
				break;
			}

			if (!NT_SUCCESS(NtAlertResumeThread(hThread, nullptr)))
			{
				wprintf(L"wmain: NtAlertResumeThread() error.\n");
			}
		} while (false);

		if (hThread) CloseHandle(hThread);
		hThread = nullptr;
	}

	if (!VirtualFreeEx(hProcess, memPtr, 0, MEM_RELEASE))
	{
		wprintf(L"wmain: VirtualFreeEx() error. (%d)\n", GetLastError());
		return 0;
	}

	if (hProcess) CloseHandle(hProcess);
	hProcess = nullptr;

	return 0;
}