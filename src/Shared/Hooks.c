#include "..\Shared\Valkyrie.h"

// Unhook the function at UnhookAddress, return TRUE if unhooked, FALSE if not
BOOL UnhookInline(VOID *UnhookAddress, CHAR *ModuleName){
    LDR_DATA_TABLE_ENTRY *Module = GetLoadedModule(ModuleName);
    PVOID Address = UnhookAddress;
    SIZE_T NumberOfBytesToProtect = 0x1000;
    ULONG NewAccessProtection = PAGE_READWRITE;
    ULONG OldAccessProtection = 0;

    DWORD UnhookIncrement = 0;
    DWORD Offset = (BYTE *)UnhookAddress - (BYTE *)Module->DllBase;

    // The clean module is opened as a file on disk.
    FILE *CleanModule = _wfopen(Module->FullDllName.Buffer, L"rb");
    if(!CleanModule){
        wprintf(L"[ERROR] Failed to open %ls.\n", Module->FullDllName.Buffer);
        return FALSE;
    }

    // Set the file pointer to the hooked function address
    if(fseek(CleanModule, Offset, SEEK_SET) != 0){
        wprintf(L"[ERROR] Failed to jump to function offset in %ls.\n", Module->FullDllName.Buffer);
    }

    BYTE CleanBuffer[8];
    fread(CleanBuffer, sizeof(CleanBuffer), 1, CleanModule);

    LPVOID SysAddr_NtProtectVirtualMemory = (LPVOID)((BYTE *)CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_NTDLL), HASH_FUNC_NTPROTECTVIRTUALMEMORY) + 0x12);
    NTSTATUS Status = Sys_NtProtectVirtualMemory((HANDLE)-1, &Address, &NumberOfBytesToProtect, NewAccessProtection, &OldAccessProtection, SysAddr_NtProtectVirtualMemory);

    if(NT_SUCCESS(Status)){
        while(*(ULONGLONG *)UnhookAddress != *(ULONGLONG *)CleanBuffer){
            for(DWORD i = 0; i < sizeof(CleanBuffer); i++){
                *(BYTE *)UnhookAddress = CleanBuffer[i];
                UnhookAddress = (BYTE *)UnhookAddress + 1;
                UnhookIncrement += 1;
            }
            fread(CleanBuffer, sizeof(CleanBuffer), 1, CleanModule);   
        }
        fclose(CleanModule);
        UnhookAddress = (BYTE *)UnhookAddress - UnhookIncrement;

        Status = Sys_NtProtectVirtualMemory((HANDLE)-1, &Address, &NumberOfBytesToProtect, OldAccessProtection, &OldAccessProtection, SysAddr_NtProtectVirtualMemory);
        return TRUE;
    } else {
        wprintf(L"[ERROR] Failed to modify %ls page permissions.\n", Module->FullDllName.Buffer);
        return FALSE;
    }
}

// Unhook the function at IATFunctionAddress, return TRUE if unhooekd, FALSE if not
BOOL UnhookIAT(ULONGLONG *IATFunctionAddress, ULONGLONG TrueFunctionAddress){
    NTSTATUS Status;
    ULONG    OldProtect;
    SIZE_T   RegionSize = sizeof(ULONGLONG);
    PVOID    TargetAddress = (PVOID)IATFunctionAddress;
    LPVOID   SysAddr_NtProtectVirtualMemory = (LPVOID)((BYTE *)CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_NTDLL), HASH_FUNC_NTPROTECTVIRTUALMEMORY) + 0x12);

    Status = Sys_NtProtectVirtualMemory((HANDLE)-1, &TargetAddress, &RegionSize, PAGE_READWRITE, &OldProtect, SysAddr_NtProtectVirtualMemory);

    if(NT_SUCCESS(Status)){
        *IATFunctionAddress = TrueFunctionAddress;
        Sys_NtProtectVirtualMemory((HANDLE)-1, &TargetAddress, &RegionSize, PAGE_READONLY, &OldProtect, SysAddr_NtProtectVirtualMemory);
    } else {
        return FALSE;
    }
    return TRUE;
}

// Check if FunctionName is a known false positive for a rule that would otherwise indicate a hook, returns TRUE if exempt, FALSE if not
BOOL CheckFunctionHookException(CHAR *FunctionName){

    // For exported functions that legitimately exhibit behaviour usually indicative of tampering
    CHAR *FUNCTION_HOOK_EXCEPTIONS[] = {
        "memset", // msvcrt.dll!memset legitimately jumps to a non-exported function in msvcrt.dll's .text section
        // List more here when discovered
        NULL
    };

    for(DWORD i = 0; FUNCTION_HOOK_EXCEPTIONS[i] != NULL; i++){
        if(strcmp(FunctionName, FUNCTION_HOOK_EXCEPTIONS[i]) == 0){
            return TRUE;
        }
    }
    return FALSE;
}