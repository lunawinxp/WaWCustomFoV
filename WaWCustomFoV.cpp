#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>

int main() {
    DWORD pid = 0;
    PROCESSENTRY32 pe{ sizeof(pe) };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(snap, &pe); Process32Next(snap, &pe); )
        if (!wcscmp(pe.szExeFile, L"CoDWaW.exe")) { pid = pe.th32ProcessID; break; }
    CloseHandle(snap);
    if (!pid) { std::cerr << "Process not found.\n"; std::cin.get(); return 1; }

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!h) { std::cerr << "Failed to open process.\n"; std::cin.get(); return 1; }

    std::vector<int> pat;
    std::istringstream ss("8B 55 ? 83 FA 01");
    for (std::string b; ss >> b;)
        pat.push_back(b == "?" ? -1 : std::stoi(b, nullptr, 16));

    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORY_BASIC_INFORMATION m; uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress, f = 0;
    std::vector<BYTE> buf;

    for (; a < (uintptr_t)si.lpMaximumApplicationAddress; a += m.RegionSize) {
        if (!VirtualQueryEx(h, (LPCVOID)a, &m, sizeof(m))) break;
        if (!(m.State & MEM_COMMIT)) continue;
        if (!(m.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_READONLY))) continue;

        buf.resize(m.RegionSize); SIZE_T r;
        if (!ReadProcessMemory(h, m.BaseAddress, buf.data(), m.RegionSize, &r)) continue;

        for (SIZE_T i = 0; i <= r - pat.size(); ++i) {
            bool match = true;
            for (SIZE_T j = 0; j < pat.size(); ++j)
                if (pat[j] != -1 && buf[i + j] != pat[j]) { match = false; break; }
            if (match) { f = a + i; break; }
        }
        if (f) break;
    }

    if (!f) { std::cerr << "Pattern not found.\n"; std::cin.get(); return 1; }

    BYTE patch[] = { 0xE9, 0xEA, 0x00, 0x00, 0x00 };
    SIZE_T w;
    if (!WriteProcessMemory(h, (LPVOID)f, patch, sizeof(patch), &w)) {
        std::cerr << "Patch failed.\n"; std::cin.get(); return 1;
    }

    std::cout << "Patched!\nSet cg_fov 90 in console now!\nPress enter to close window...";
    CloseHandle(h);
    std::cin.get();
    return 0;
}
