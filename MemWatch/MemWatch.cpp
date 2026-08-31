#include "MemWatch.hpp"

bool findproc(std::wstring appnamexe, HANDLE handle, PROCESSENTRY32* pentry) {
	bool cproc = Process32First(handle, pentry);
	bool found = false;
	while (cproc != false) {
		cproc = Process32Next(handle, pentry);
		if (appnamexe == pentry->szExeFile) {
			found = true;
			break;
		}
	}
	return found;
}

int getmem(HANDLE hProcess, HANDLE hHeapList, std::string str_to_find) {
	bool found = false;
	HEAPLIST32 hlentry{};
	HEAPENTRY32 hentry{};
	MEMORY_BASIC_INFORMATION basicinf{};

	hlentry.dwSize = sizeof(HEAPLIST32);
	hentry.dwSize = sizeof(HEAPENTRY32);

	size_t bytes_read = 0;

	bool hlcheck = Heap32ListFirst(hHeapList, &hlentry);
	int hcounter = 1;
	while (hlcheck) {
		int bcounter = 0;
		int ccounter = 0;
		std::cout << "Heap Number: " << hcounter << std::endl;

		bool hcheck = Heap32First(&hentry, hlentry.th32ProcessID, hlentry.th32HeapID);

		bcounter++;

		if (hentry.dwAddress == 0) {
			return -1;
		}

		std::vector<std::byte>tmpbuff(hentry.dwBlockSize);
		if (!ReadProcessMemory(hProcess, reinterpret_cast<void*>(hentry.dwAddress), tmpbuff.data(), hentry.dwBlockSize, &bytes_read)) {
			std::cout << "Read Failed" << std::endl;
		}

		std::cout << "Block Size: " << hentry.dwBlockSize << " ";
		std::cout << "Data Size: " << tmpbuff.size() << std::endl;
		while (hcheck) {
			hcheck = Heap32Next(&hentry);
			bcounter++;
			ULONG_PTR current_addy = hentry.dwAddress;
			size_t total_read = 0;
			while (total_read < hentry.dwBlockSize)
			{
				int qrd = VirtualQueryEx(hProcess, reinterpret_cast<void*>(current_addy), &basicinf, sizeof(MEMORY_BASIC_INFORMATION));
				if (qrd == 0) {
					std::cout << "FAILED TO QUERY, CHECK PROCESS PERMISSIONS" << std::endl;
					exit(-1);
				}

				size_t bytes_to_read = hentry.dwBlockSize - total_read > basicinf.RegionSize ?
					reinterpret_cast<ULONG_PTR>(basicinf.BaseAddress) + basicinf.RegionSize - current_addy : hentry.dwBlockSize - total_read;

				if (basicinf.State != MEM_COMMIT || basicinf.Protect & PAGE_NOACCESS) {
					total_read += bytes_to_read;
					current_addy += bytes_to_read;
					std::cout << "Block Size: NO ACCESS ";
					std::cout << "Data Size: NO ACCESS" << std::endl;
					continue;
				}

				if (bytes_to_read > tmpbuff.size()) tmpbuff.resize(bytes_to_read);

				if (!ReadProcessMemory(hProcess, reinterpret_cast<void*>(current_addy), tmpbuff.data(), bytes_to_read, &bytes_read)) {
					std::cout << "Read Failed" << std::endl;
				}
				std::cout << "Block Size: " << hentry.dwBlockSize << " ";
				std::cout << "Data Size: " << tmpbuff.size() << std::endl;

				ccounter++;

				total_read += bytes_read;
				current_addy += bytes_read;

				std::string str(reinterpret_cast<char*>(tmpbuff.data()), tmpbuff.size());

				std::string::iterator idx = std::search(str.begin(), str.end(), str_to_find.begin(), str_to_find.end());
				if (idx != str.end()) {
					found = true;
				}
			}
		}
		std::cout << "Blocks in that heap: " << bcounter << std::endl;
		std::cout << "Chunks in that heap: " << ccounter << std::endl;
		hlcheck = Heap32ListNext(hHeapList, &hlentry);
		hcounter++;
	}
	return found;
}

ProcHeapScanner::ProcHeapScanner(DWORD pid) {
	this->pid = pid;
	hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
	hHeapList = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);

	hlentry.dwSize = sizeof(HEAPLIST32);
	hentry.dwSize = sizeof(HEAPENTRY32);

	hlcheck = Heap32ListFirst(hHeapList, &hlentry);

	if (!hlcheck) return;

	hcheck = Heap32First(&hentry, hlentry.th32ProcessID, hlentry.th32HeapID);

	if (!hcheck) return;

	current_addy = hentry.dwAddress;

	QueryAndRead();

	heapcounter++;
	blockcounter++;
	chunkcounter++;
}

ProcHeapScanner::~ProcHeapScanner() {
	CloseHandle(hHeapList);
	CloseHandle(hProcess);
}

void ProcHeapScanner::QueryAndRead() {
	int qrd = VirtualQueryEx(hProcess, reinterpret_cast<void*>(current_addy), &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	if (qrd == 0) {
		std::cerr << "FAILED TO QUERY, CHECK PROCESS PERMISSIONS" << std::endl;
		return;
	}

	ULONG_PTR region_end = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;

	bytes_to_read = std::min<ULONG_PTR>(region_end - current_addy, hentry.dwBlockSize - total_read);

	if (mbi.State != MEM_COMMIT || mbi.Protect & PAGE_NOACCESS) {
		total_read += bytes_to_read;
		current_addy += bytes_to_read;
		std::cout << "NO ACCESS" << std::endl;
		return;
	}

	if (bytes_to_read > data.size()) data.resize(bytes_to_read);

	size_t bytes_read = 0;
	if (!ReadProcessMemory(hProcess, reinterpret_cast<void*>(current_addy), data.data(), bytes_to_read, &bytes_read)) {
		std::cerr << "READ HAS FAILED OR IS INCOMPLETE" << std::endl;
		std::cerr << "ERROR: " << GetLastError() << std::endl;
		std::cout << "State: " << mbi.State << std::endl;
		std::cout << "Protect: " << mbi.Protect << std::endl;
		std::cout << "Address: " << LPVOID(current_addy) << " Bytes to read: " << bytes_to_read << std::endl;
		std::cout << "Page Base Address: " << mbi.BaseAddress << std::endl;
		std::cout << "Delta: " << current_addy - ULONG_PTR(mbi.BaseAddress) << std::endl;


		std::cout << "Total read " << total_read << std::endl;
		std::cout << "Block size: " << hentry.dwBlockSize << std::endl;
		exit(-1);
	}

	std::cout << "Address: " << LPVOID(current_addy) << std::endl;
	std::cout << "bytes read: " << bytes_read << std::endl;
	std::cout << "Block Size: " << hentry.dwBlockSize << " ";
	std::cout << "Data Size: " << data.size() << std::endl;
	total_read += bytes_read;
	current_addy += bytes_read;
}

int ProcHeapScanner::NextChunk() {
	if (total_read >= hentry.dwBlockSize) {
		std::cout << "GOING TO NEXT BLOCK" << std::endl;
		hcheck = Heap32Next(&hentry);
		if (hcheck) blockcounter++;
		total_read = 0;
		bytes_to_read = 0;
		current_addy = hentry.dwAddress;

	}

	if (!hcheck) {
		//std::cout << "GOING TO NEXT HEAP" << std::endl;
		hlcheck = Heap32ListNext(hHeapList, &hlentry);
		if (hlcheck) heapcounter++;
	}

	if (!hlcheck) {
		std::cout << "CHECK: " << hlcheck << std::endl;
		return -1;
	}

	QueryAndRead();

	chunkcounter++;

	return 0;
}

void ProcHeapScanner::NextHeap() {

	hlcheck = Heap32ListNext(hHeapList, &hlentry);
	hcheck = Heap32First(&hentry, hlentry.th32ProcessID, hlentry.th32HeapID);

	if (!hlcheck) return;

	current_addy = hentry.dwAddress;

	QueryAndRead();
}

void ProcHeapScanner::NextBlock() {

	hcheck = Heap32Next(&hentry);

	if (!hcheck) return;

	current_addy = hentry.dwAddress;

	QueryAndRead();
}

std::vector<std::byte> ProcHeapScanner::GetData() {
	return data;
}

void ProcHeapScanner::DisplayStats() {
	std::cout << "Heap Count: " << heapcounter << std::endl;
	std::cout << "Block Count: " << blockcounter << std::endl;
	std::cout << "Chunk Count: " << chunkcounter << std::endl;
}