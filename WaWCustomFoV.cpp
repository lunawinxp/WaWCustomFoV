#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <sstream>

DWORD GetProcessIdByName(const std::wstring& name) {
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = 0;

    if (Process32First(snapshot, &entry)) {
        do {
            if (name == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

std::vector<int> ParsePattern(const std::string& patternStr) {
    std::vector<int> pattern;
    std::istringstream iss(patternStr);
    std::string byteStr;

    while (iss >> byteStr) {
        if (byteStr == "?" || byteStr == "??") {
            pattern.push_back(-1); // wildcard
        }
        else {
            pattern.push_back(std::stoi(byteStr, nullptr, 16));
        }
    }

    return pattern;
}

bool ComparePattern(const BYTE* data, const std::vector<int>& pattern) {
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] != -1 && data[i] != (BYTE)pattern[i])
            return false;
    }
    return true;
}

uintptr_t FindPattern(HANDLE hProcess, BYTE* base, SIZE_T size, const std::vector<int>& pattern) {
    std::vector<BYTE> buffer(size);
    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, base, buffer.data(), size, &bytesRead))
        return 0;

    for (SIZE_T i = 0; i < bytesRead - pattern.size(); ++i) {
        if (ComparePattern(&buffer[i], pattern)) {
            return (uintptr_t)base + i;
        }
    }
    return 0;
}

int main() {
    const std::wstring targetProcess = L"CoDWaW.exe";
    std::string targetProcessStr(targetProcess.begin(), targetProcess.end());
    const std::string patternStr = "8B 55 ? 83 FA 01";
    const BYTE patchBytes[] = { 0xE9, 0xEA, 0x00, 0x00, 0x00 };

    std::vector<int> pattern = ParsePattern(patternStr);

    DWORD pid = GetProcessIdByName(targetProcess);
    if (!pid) {
        std::cout << "Process (" << targetProcessStr << ") not found.\n";
        system("pause");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "Failed to open process (" << targetProcessStr << ")\n";
        system("pause");
        return 1;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uintptr_t addr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t foundAddr = 0;

    while (addr < maxAddr) {
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
            bool isReadable = (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi.Protect & PAGE_READWRITE) ||
                (mbi.Protect & PAGE_READONLY);

            if (mbi.State == MEM_COMMIT && isReadable) {
                foundAddr = FindPattern(hProcess, (BYTE*)mbi.BaseAddress, mbi.RegionSize, pattern);
                if (foundAddr)
                    break;
            }
            addr += mbi.RegionSize;
        }
        else {
            break;
        }
    }

    if (foundAddr) {
        std::cout << "Pattern found at: 0x" << std::hex << foundAddr << "\n";
        SIZE_T written;
        if (WriteProcessMemory(hProcess, (LPVOID)foundAddr, patchBytes, sizeof(patchBytes), &written)) {
            std::cout << "Patch applied successfully. In the console set 'cg_fov 90' now!\n";
            system("pause");
        }
        else {
            std::cout << "Failed to write to memory.\n";
            system("pause");
        }
    }
    else {
        std::cout << "Pattern not found.\n";
        system("pause");
    }

    CloseHandle(hProcess);
    return 0;
}
