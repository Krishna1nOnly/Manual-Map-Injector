#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>

using namespace std;

// Console color constants
#define COLOR_DEFAULT 7
#define COLOR_SUCCESS 10
#define COLOR_ERROR 12
#define COLOR_WARNING 14
#define COLOR_INFO 11

// Function to set console text color
void SetConsoleColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

// Manual mapping structures and functions
using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

struct MANUAL_MAPPING_DATA {
    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
    f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
    BYTE* pbase;
    HINSTANCE hMod;
    DWORD fdwReasonParam;
    LPVOID reservedParam;
    BOOL SEHSupport;
};

// Logging macros
#define LOG_SUCCESS(text, ...) { SetConsoleColor(COLOR_SUCCESS); printf("[+] "); printf(text, __VA_ARGS__); SetConsoleColor(COLOR_DEFAULT); }
#define LOG_ERROR(text, ...) { SetConsoleColor(COLOR_ERROR); printf("[-] "); printf(text, __VA_ARGS__); SetConsoleColor(COLOR_DEFAULT); }
#define LOG_WARNING(text, ...) { SetConsoleColor(COLOR_WARNING); printf("[!] "); printf(text, __VA_ARGS__); SetConsoleColor(COLOR_DEFAULT); }
#define LOG_INFO(text, ...) { SetConsoleColor(COLOR_INFO); printf("[*] "); printf(text, __VA_ARGS__); SetConsoleColor(COLOR_DEFAULT); }

// Architecture detection
#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#endif

// Function prototypes
bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
DWORD GetProcessIdByName(const wstring& name);
bool IsCorrectTargetArchitecture(HANDLE hProc);
void EnsureAdminPrivileges();
void EnableDebugPrivileges();
BYTE* ReadDllFile(const wstring& path, SIZE_T& fileSize);

#pragma runtime_checks("", off)
#pragma optimize("", off)

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData) return;

    BYTE* pBase = pData->pbase;
    auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
#ifdef _WIN64
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;
#endif

    // Relocation handling
    BYTE* LocationDelta = pBase - pOpt->ImageBase;
    if (LocationDelta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>((BYTE*)pRelocData + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
            UINT count = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
            for (UINT i = 0; i < count; ++i) {
                if (RELOC_FLAG(pRelativeInfo[i])) {
                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + (pRelativeInfo[i] & 0xFFF));
                    *pPatch += (UINT_PTR)LocationDelta;
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>((BYTE*)pRelocData + pRelocData->SizeOfBlock);
        }
    }

    // Import handling
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDesc->Name) {
            char* szMod = (char*)(pBase + pImportDesc->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDesc->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDesc->FirstThunk);
            if (!pThunkRef) pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
                }
                else {
                    auto* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDesc;
        }
    }

    // TLS handling
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
        for (; pCallback && *pCallback; ++pCallback)
            (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    // Exception handling (x64 only)
#ifdef _WIN64
    if (pData->SEHSupport && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        _RtlAddFunctionTable(
            (PRUNTIME_FUNCTION)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
            pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
            (DWORD64)pBase);
    }
#endif

    // Execute DllMain
    auto DllMain = (f_DLL_ENTRY_POINT)(pBase + pOpt->AddressOfEntryPoint);
    DllMain(pBase, pData->fdwReasonParam, pData->reservedParam);
}
#pragma runtime_checks("", restore)
#pragma optimize("", on)

bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)pSrcData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_ERROR("Invalid DOS signature\n");
        return false;
    }

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(pSrcData + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        LOG_ERROR("Invalid NT signature\n");
        return false;
    }

    if (ntHeader->FileHeader.Machine != CURRENT_ARCH) {
        LOG_ERROR("Architecture mismatch\n");
        return false;
    }

    BYTE* targetBase = (BYTE*)VirtualAllocEx(hProc, nullptr, ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!targetBase) {
        LOG_ERROR("Memory allocation failed (0x%X)\n", GetLastError());
        return false;
    }

    MANUAL_MAPPING_DATA data = {};
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
    data.pRtlAddFunctionTable = RtlAddFunctionTable;
#endif
    data.pbase = targetBase;
    data.fdwReasonParam = DLL_PROCESS_ATTACH;
    data.SEHSupport = true;

    // Write headers
    if (!WriteProcessMemory(hProc, targetBase, pSrcData, 0x1000, nullptr)) {
        LOG_ERROR("Failed to write headers (0x%X)\n", GetLastError());
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        return false;
    }

    // Write sections
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
    for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->SizeOfRawData == 0) continue;

        if (!WriteProcessMemory(hProc, targetBase + section->VirtualAddress,
            pSrcData + section->PointerToRawData,
            section->SizeOfRawData, nullptr)) {
            LOG_ERROR("Failed to write section (0x%X)\n", GetLastError());
            VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
            return false;
        }
    }

    // Allocate and write shellcode
    void* remoteData = VirtualAllocEx(hProc, nullptr, sizeof(data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    void* remoteShell = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteData || !remoteShell) {
        LOG_ERROR("Shellcode allocation failed\n");
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteData, &data, sizeof(data), nullptr) ||
        !WriteProcessMemory(hProc, remoteShell, (LPVOID)Shellcode, 0x1000, nullptr)) {
        LOG_ERROR("Failed to write shellcode (0x%X)\n", GetLastError());
        VirtualFreeEx(hProc, targetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);
        return false;
    }

    // Execute shellcode
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remoteShell, remoteData, 0, nullptr);
    if (!hThread) {
        LOG_ERROR("Thread creation failed (0x%X)\n", GetLastError());
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // Cleanup
    VirtualFreeEx(hProc, remoteData, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, remoteShell, 0, MEM_RELEASE);

    return true;
}

DWORD GetProcessIdByName(const wstring& name) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Snapshot failed (0x%X)\n", GetLastError());
        return 0;
    }

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, name.c_str()) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    LOG_ERROR("Process not found: %ls\n", name.c_str());
    return 0;
}

bool IsCorrectTargetArchitecture(HANDLE hProc) {
    BOOL bTarget = FALSE;
    if (!IsWow64Process(hProc, &bTarget)) {
        LOG_ERROR("Architecture check failed (0x%X)\n", GetLastError());
        return false;
    }

    BOOL bHost = FALSE;
    IsWow64Process(GetCurrentProcess(), &bHost);

    return (bTarget == bHost);
}

void EnsureAdminPrivileges() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isAdmin) {
        LOG_ERROR("Administrator privileges required\n");
        ExitProcess(1);
    }

    LOG_SUCCESS("Running with administrator privileges\n");
}

void EnableDebugPrivileges() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPrivileges.Privileges[0].Luid);
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        CloseHandle(hToken);
    }
}

BYTE* ReadDllFile(const wstring& path, SIZE_T& fileSize) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Could not open DLL (0x%X)\n", GetLastError());
        return nullptr;
    }

    fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        LOG_ERROR("Invalid file size (0x%X)\n", GetLastError());
        CloseHandle(hFile);
        return nullptr;
    }

    BYTE* pData = new BYTE[fileSize];
    DWORD bytesRead;
    if (!ReadFile(hFile, pData, fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        LOG_ERROR("Read failed (0x%X)\n", GetLastError());
        delete[] pData;
        CloseHandle(hFile);
        return nullptr;
    }

    CloseHandle(hFile);
    return pData;
}

int main() {
    SetConsoleTitle(L"Advance Manual Mapper");
    LOG_INFO("----- DLL Injector -----\n");
    LOG_INFO("Advance DLL Injector Devloped By Krishna1nOnly\n");
    LOG_INFO("Github:https://github.com/Krishna1nOnly\n");
    EnsureAdminPrivileges();
    EnableDebugPrivileges();

    wstring processName;
    wstring dllPath;

    LOG_INFO("Enter target process name: ");
    wcin >> processName;

    LOG_INFO("Enter DLL path: ");
    wcin >> dllPath;

    SIZE_T dllSize = 0;
    BYTE* pDllData = ReadDllFile(dllPath, dllSize);
    if (!pDllData) {
        system("pause");
        return -1;
    }

    DWORD PID = GetProcessIdByName(processName);
    if (PID == 0) {
        delete[] pDllData;
        system("pause");
        return -1;
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc) {
        LOG_ERROR("OpenProcess failed (0x%X)\n", GetLastError());
        delete[] pDllData;
        system("pause");
        return -2;
    }

    if (!IsCorrectTargetArchitecture(hProc)) {
        CloseHandle(hProc);
        delete[] pDllData;
        system("pause");
        return -3;
    }

    LOG_INFO("Injecting DLL...\n");
    if (ManualMapDll(hProc, pDllData, dllSize)) {
        LOG_SUCCESS("Injection successful!\n");
    }
    else {
        LOG_ERROR("Injection failed\n");
    }

    CloseHandle(hProc);
    delete[] pDllData;

    system("pause");
    return 0;
}