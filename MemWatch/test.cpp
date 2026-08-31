#include <iostream>
#include <format>
#include "MemWatch.hpp"

#pragma comment(lib, "dbghelp.lib")
void func(DWORD pid) {
	HANDLE hHeapList = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);

	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);

	int counter = getmem(hProcess, hHeapList, "afgthfdzgsf");
}

void classy(DWORD pid) {
	int result = 0;
	ProcHeapScanner scanner(pid);

	while (!result) {
		result = scanner.NextChunk();

		//data = scanner.GetData();
	}

	scanner.DisplayStats();
}

int main() {

	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 pentry;
	pentry.dwSize = sizeof(PROCESSENTRY32);

	std::wstring AppName = L"SecureApp.exe";

	DWORD found = findproc(AppName, handle, &pentry);

	if (!found) {
		std::cout << "Could not find application" << std::endl;
		return -1;
	}

	DWORD pid = pentry.th32ProcessID;

	//func(pid);

	classy(pid);

	
}