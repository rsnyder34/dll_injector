#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#define _MBCS
#define print(...) std::cout << __VA_ARGS__ << "\n"
#define error(...) std::cout << __VA_ARGS__ << "\n"

DWORD FindProcID(const char* p_name)
{
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (!snap)
    {
        error("Creating snapshot failed");
        return pid;
    }
    PROCESSENTRY32 p_entry;
    p_entry.dwSize = sizeof(PROCESSENTRY32);

    do
    {
        if (!strcmp(p_entry.szExeFile, p_name))
        {
            pid = p_entry.th32ProcessID;
            print(p_name << " has the PID of: " << pid);
            return pid;
        }
    } while (Process32Next(snap, &p_entry));
    return pid;
}



bool Inject(DWORD pid, const char* file_loc)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!hProc)
    {
        error("Failed to get handle to process");
        return false;
    }
    void* mem_loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem_loc)
    {
        error("Failed to allocate memory");
        return false;
    }
    print("Allocating memory @: " << mem_loc);
    bool wpm = WriteProcessMemory(hProc, mem_loc, file_loc, strlen(file_loc) + 5, 0);
    if (!wpm)
    {
        error("Failed to write file to allocated memory");
        return false;
    }

    if (!CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, mem_loc, 0, 0))
    {
        error("Failed to execute LoadLibraryA");
        return false;
    }
    print("Thread executed");
    CloseHandle(hProc);
    VirtualFree(mem_loc, MAX_PATH, MEM_RELEASE);
    return true;
}

int main(int argc, char** argv)
{
    DWORD pid = FindProcID((argv[1]));
    const char* file_name = argv[2];
    char file_loc[MAX_PATH];
    if (!GetFullPathNameA(file_name, MAX_PATH, file_loc, 0))
    {
        error("Failed to find the file");
        return -1;
    }
    if (!Inject(pid, file_loc))
    {
        error("Inject function failed");
        return -3;
    }
    print("Process has been injected");
    return 0;
}