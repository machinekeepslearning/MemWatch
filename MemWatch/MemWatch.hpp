#pragma once
#include <memory>
#include <string>
#include <vector>
#include <assert.h>
#include <algorithm>
#include <stdexcept>

#include <Windows.h>
#include <TlHelp32.h>
#include <processthreadsapi.h>
#include <heapapi.h>
#include <iostream>
#include <Psapi.h>
#include <DbgHelp.h>


bool findproc(std::wstring appnamexe, HANDLE handle, PROCESSENTRY32* pentry);

int getmem(HANDLE hProcess, HANDLE hHeapList, std::string str_to_find);

class ProcHeapScanner {
	HANDLE hHeapList;
	HANDLE hProcess;
	DWORD pid;
	HEAPLIST32 hlentry{};
	HEAPENTRY32 hentry{};
	MEMORY_BASIC_INFORMATION mbi{};

	std::vector<std::byte> data;

	size_t total_read = 0;
	size_t bytes_to_read = 0;
	ULONG_PTR current_addy{};

	int heapcounter = 0;
	int blockcounter = 0;
	int chunkcounter = 0;

	bool hcheck = false;
	bool hlcheck = false;

	int QueryAndRead();
public:
	ProcHeapScanner(DWORD pid);
	~ProcHeapScanner();

	int FirstChunk();

	int NextChunk();

	int NextHeap();

	int NextBlock();

	std::vector<std::byte> GetData();

	void DisplayStats();
};