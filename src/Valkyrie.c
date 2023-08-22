#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

// Only works on x64 Win 10.

// TODO:
// Find out what the 0xc00 is.

// REFERENCES
// ----------
// Sektor7
// https://www.amd.com/system/files/TechDocs/40332.pdf
// https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)
// https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
// https://j00ru.vexillium.org/syscalls/nt/64/

// Sys_NtProtectVirtualMemory is implemented in Syscall.asm
extern NTSTATUS Sys_NtProtectVirtualMemory(HANDLE  ProcessHandle,
                                           PVOID   *BaseAddress,
                                           PSIZE_T NumberOfBytesToProtect,
                                           ULONG   NewAccessProtection,
                                           PULONG  OldAccessProtection,
                                           LPVOID  SysCallAddress);

BOOL ARG_SCAN       = FALSE;
BOOL ARG_UNHOOK     = FALSE;
BOOL ARG_VERBOSE    = FALSE;
BOOL ARG_AGGRESSIVE = FALSE;

FARPROC CustomGetProcAddress(HMODULE BaseAddress, char *ProcName){

    // This is a custom implementation of GetProcAddress designed to manually carry out the same task as the original.
    // With the goal of avoiding calling potentially hooked functions, implementing necessary ones manually is important.
    // The purpose of this function is to return the virtual address of a desired exported function.

    // This function takes the base address of a module and walks the PE headers to locate the Export Address Table (EAT).
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);

    DWORD *EAT             = (DWORD *)(ExportDirectory->AddressOfFunctions    + (BYTE *)BaseAddress);
    DWORD *FunctionName    = (DWORD *)(ExportDirectory->AddressOfNames        + (BYTE *)BaseAddress);
    WORD  *FunctionOrdinal = (WORD  *)(ExportDirectory->AddressOfNameOrdinals + (BYTE *)BaseAddress);

    // Upon locating the EAT, it searches each exported function's name until it matches the desired "ProcName" parameter.
    for(int i = 0; i < ExportDirectory->NumberOfNames; i++){
        char *CurrentFunctionName = (char *)(FunctionName[i] + (BYTE *)BaseAddress);
        if(strcmp(CurrentFunctionName, ProcName) == 0){
            // Upon locating the desired function in the module's EAT, it adds the RVA to the module base and returns its location in memory.
            void *FunctionAddress = (void *)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);
            return (FARPROC)FunctionAddress;
        }
    }
    return NULL;
}

HMODULE CustomGetModuleHandle(char *ModuleName){

    // This is another custom implementation, this time of GetModuleHandle designed to manually carry out the same task as the original.
    // The purpose of this function is to search loaded modules in the current process and return a handle to the specified module.

    // This function searches the Thread Environment Block (TEB) located in the GS CPU register for the Process Environment Block (PEB) at offset 0x60 (in x64).
    // A linked list of every currently loaded module resides inside the InMemoryOrderModuleList member of the PEB Loader, this is what will be parsed.
    PEB *ProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Loader = (PEB_LDR_DATA *)ProcessEnvironmentBlock->Ldr;
    LIST_ENTRY *ModuleList = &Loader->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentEntry = ModuleList->Flink;

    // If NULL is provided as a parameter to this function, it will return the base address of the module that called it (Valkyrie).
    // Otherwise, it will convert the desired ModuleName to a wide string for comparison because modules inside InMemoryOrderModuleList are named with wide strings.
    if(ModuleName == NULL){
        LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));
        return (HMODULE)DataCurrentListEntry->DllBase;
    } else {
        WCHAR WideModuleName[256];
        size_t len = mbstowcs(WideModuleName, ModuleName, sizeof(WideModuleName) / sizeof(WCHAR));

        // It's a linked list, when the CurrentEntry loops back around to the first entry (ModuleList), the list has been exhausted and the module hasn't been found.
        while(CurrentEntry != ModuleList){
            LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));

            // Reserved4 is a (for some reason) undocumented member of LDR_DATA_TABLE_ENTRY.
            // It is simply the base DLL name without the path attached ("ntdll.dll" instead of "C:\Windows\System32\ntdll.dll").
            // https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/_LDR_DATA_TABLE_ENTRY
            UNICODE_STRING *BaseDllName = (UNICODE_STRING *)DataCurrentListEntry->Reserved4;

            size_t DllNameLen = wcslen(BaseDllName->Buffer);
            WCHAR *cmpDllName = malloc(DllNameLen * sizeof(WCHAR));
            wcscpy_s(cmpDllName, DllNameLen * sizeof(WORD), BaseDllName->Buffer);

            if(wcscmp(_wcslwr(cmpDllName), _wcslwr(WideModuleName)) == 0){
                // If the names match, you've found the right module in the list and can return its base as a HMODULE.
                return (HMODULE)DataCurrentListEntry->DllBase; 
            }
            // If the names don't match, you've got the wrong module entry and iterate onto the next.
            CurrentEntry = CurrentEntry->Flink;
            
            free(cmpDllName);
            cmpDllName = NULL;
        }
        return NULL;
    }
}

void ScanModuleFunctions(HMODULE BaseAddress){

    // This function is a little hacky.
    // It will be called only in aggressive mode because it scans every single exported function of a module regardless of whether the function is imported or not.
    // This is useful for tools that may dynamically resolve functions at runtime instead of importing because it'll still catch hooks.

    // The idea was to create a static array of module names that have been scanned by this function to ensure a module would never be scanned twice.
    // Before scanning a module, the function checks to see if the module exists in the array, if it doesn't, it needs to be scanned.
    // In hindsight, I don't see a scenario in which a module would be passed to this function twice considering the function is only called once.
    // We'll say it was great foresight for scalability and pretend it's necessary.

    static BOOL init = TRUE;
    static char **ScannedModules = NULL;
    
    // Without knowing how many modules might potentially be loaded, the array starts at a fixed size and expands if there's somehow more than 20 modules.
    int ModuleCount = 20; // This is only an initial value.

    if(init){

        // Static variables hold their values across different function calls meaning the array will be created on the first call only and persist across others.
        ScannedModules = calloc(ModuleCount, sizeof(char *));
        init = FALSE;
    }

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);
    char *ModuleName = ExportDirectory->Name + (BYTE *)BaseAddress;

    // The function scans the array to ensure a module hasn't been scanned before.
    if(ScannedModules){
        for(int i = 0; i < ModuleCount; i++){
            if(ScannedModules[i]){
                if(strcmp(ScannedModules[i], ModuleName) == 0){
                    return;
                }
            }
        }

        // If the final spot in the current array is occupied, the array expands by 10 extra spots.
        if(ScannedModules[ModuleCount - 1] != NULL){
            
            // The array is duplicated so the original can be freed and expanded.
            char **tmpScannedModules = calloc(ModuleCount, sizeof(char *));
            for(int i = 0; i < ModuleCount; i++){
                tmpScannedModules[i] = ScannedModules[i];
            }
            free(ScannedModules);
            ScannedModules = NULL;

            ModuleCount += 10;
            ScannedModules = calloc(ModuleCount, sizeof(char *));

            // Once the array is expanded, the module names inside are returned to it and the duplicate is freed.
            for(int i = 0; i < ModuleCount - 10; i++){
                ScannedModules[i] = tmpScannedModules[i];
            }
            free(tmpScannedModules);
            tmpScannedModules = NULL;
        }

        // Now the current module name will be added to the array in its first empty slot as evidence of its current scanning.
        for(int i = 0; i < ModuleCount; i++){
            if(!ScannedModules[i]){
                ScannedModules[i] = (char *)malloc(strlen(ModuleName) + 1);
                strcpy_s((char *)ScannedModules[i], strlen(ModuleName) + 1, ModuleName);
                break;  
            }
        }
    }

    DWORD *EAT             = (DWORD *)(ExportDirectory->AddressOfFunctions    + (BYTE *)BaseAddress);
    DWORD *FunctionName    = (DWORD *)(ExportDirectory->AddressOfNames        + (BYTE *)BaseAddress);
    WORD  *FunctionOrdinal = (WORD  *)(ExportDirectory->AddressOfNameOrdinals + (BYTE *)BaseAddress);

    // The EAT is parsed and every function inside is checked for inline hooks.
    for(int i = 0; i < ExportDirectory->NumberOfNames; i++){
        void *CheckAddress = (void *)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);
        if(CheckForInlineHook(CheckAddress)){
            DetermineJump((BYTE *)CheckAddress);
        }
    }
    return;
}

BOOL UnhookInline(void *UnhookAddress, LDR_DATA_TABLE_ENTRY *Module){

    // This is the function where it all happens.
    // Using an indirect syscall to NtProtectVirtualMemory, the target function is made writeable to facilitate unhooking.
    // After the function in memory is made writeable, the clean function from disk is written over the hooked function in memory.

    LPVOID SysAddr_NtProtectVirtualMemory = NULL;
    PVOID Address = UnhookAddress;
    SIZE_T NumberOfBytesToProtect = 0x1000;
    ULONG NewAccessProtection = PAGE_READWRITE;
    ULONG OldAccessProtection = 0;

    FILE *CleanModule = NULL;
    DWORD UnhookIncrement = 0;
    DWORD Offset = (BYTE *)UnhookAddress - (BYTE *)Module->DllBase - 0xc00; // Why minus 0xc00? Who knows, but it works!

    // The clean module is opened as a file on disk.
    CleanModule = _wfopen(Module->FullDllName.Buffer, L"rb");
    if(!CleanModule){
        wprintf(L"[!] Unhooking: Failed to open %ls.\n", Module->FullDllName.Buffer);
        return FALSE;
    }

    // The file pointer is set to the beginning of the inline hooked function in memory.
    if(fseek(CleanModule, Offset, SEEK_SET) != 0){
        wprintf(L"[!] Unhooking: Failed to jump to function offset in %ls.\n", Module->FullDllName.Buffer);
    }

    // 8 bytes are pulled at a time from the clean module on disk into a buffer for comparison / overwriting into memory if necessary.
    unsigned char CleanBuffer[8];
    fread(CleanBuffer, sizeof(CleanBuffer), 1, CleanModule);

    // For the indirect syscall, the virtual address of NtProtectVirtualMemory's SYSCALL instruction is retrieved.
    SysAddr_NtProtectVirtualMemory = CustomGetProcAddress(CustomGetModuleHandle("ntdll.dll"), "NtProtectVirtualMemory");
    SysAddr_NtProtectVirtualMemory = (BYTE *)SysAddr_NtProtectVirtualMemory + 0x12; // Syscall is 0x12 bytes after start of function.

    // The parameters to NtProtectVirtualMemory are moved into the appropriate registers and the implementation inside Syscall.asm is called.
    // As x64 calling convention goes, the first 4 parameters go into registers, the rest on the stack.
    // This is a very easy way of accessing the syscall address inside the Syscall.asm stub - jump to its location on the stack and land on the syscall.
    NTSTATUS Status = Sys_NtProtectVirtualMemory((HANDLE)-1, &Address, &NumberOfBytesToProtect, PAGE_READWRITE, &OldAccessProtection, SysAddr_NtProtectVirtualMemory);
    if(NT_SUCCESS(Status)){

        // If the function is successfully made writeable, compare the first 8 clean bytes from disk to the first 8 tampered bytes in memory.
        // If they are different, the function is still hooked and the current 8 bytes in memory is overwritten by the current 8 bytes on disk.
        while(*(LONGLONG *)UnhookAddress != *(LONGLONG *)CleanBuffer){
            for(int i = 0; i < sizeof(CleanBuffer); i++){
                *(BYTE *)UnhookAddress = CleanBuffer[i];
                (BYTE *)UnhookAddress += 1;
                UnhookIncrement += 1;
            }
            fread(CleanBuffer, sizeof(CleanBuffer), 1, CleanModule);   
        }
        fclose(CleanModule);
        (BYTE *)UnhookAddress -= UnhookIncrement;

        // Restore the original memory protections.
        Status = Sys_NtProtectVirtualMemory((HANDLE)-1, &Address, &NumberOfBytesToProtect, OldAccessProtection, &OldAccessProtection, SysAddr_NtProtectVirtualMemory);
        return TRUE;
    } else {
        wprintf(L"[!] Unhooking: Failed to modify %ls page permissions.\n", Module->FullDllName.Buffer);
        return FALSE;
    }
}

char *GetFunctionName(HMODULE BaseAddress, void *ProcAddress){

    // This function is very similar to GetProcAddress except instead of taking a function name and returning the address, it takes the address and returns the name.

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);

    DWORD *EAT             = (DWORD *)(ExportDirectory->AddressOfFunctions    + (BYTE *)BaseAddress);
    DWORD *FunctionName    = (DWORD *)(ExportDirectory->AddressOfNames        + (BYTE *)BaseAddress);
    WORD  *FunctionOrdinal = (WORD  *)(ExportDirectory->AddressOfNameOrdinals + (BYTE *)BaseAddress);

    for(int i = 0; i < ExportDirectory->NumberOfNames; i++){
        char *CurrentFunctionName    = (char *)(FunctionName[i] + (BYTE *)BaseAddress);
        void *CurrentFunctionAddress = (void *)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);

        if(CurrentFunctionAddress == ProcAddress){
            return CurrentFunctionName;
        }
    }
    return NULL;
}

LDR_DATA_TABLE_ENTRY *DetermineModule(void *CheckAddress){

    // This function determines what module an address resides in and returns that module's LDR_DATA_TABLE_ENTRY.
    // The utility being, some functions begin with genuine jump instructions, but if the jump is determined to land inside an external module, that's a hook.

    // NOTE: DetermineModule returns the highest possible module (based on those present in InMemoryOrderModuleList).
    
    PEB *ProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Loader = (PEB_LDR_DATA *)ProcessEnvironmentBlock->Ldr;
    LIST_ENTRY *ModuleList = &Loader->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentEntry = ModuleList->Flink;

    // The module is determined by finding the loaded module with the highest base address which doesn't exceed the CheckAddress.
    void *LargestPossibleAddress  = 0x0000000000000000;

    // The modules will be searched twice. 
    // After the first search, the module the address in question belongs to will be discovered.
    while(CurrentEntry != ModuleList){
        LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));

        if(CheckAddress > DataCurrentListEntry->DllBase){
            if(DataCurrentListEntry->DllBase > LargestPossibleAddress){
                LargestPossibleAddress = DataCurrentListEntry->DllBase;
            }
        }
        CurrentEntry = CurrentEntry->Flink;
    }

    CurrentEntry = ModuleList->Flink;

    // The second search is done to find the module entry again and this time return it.
    while(CurrentEntry != ModuleList){
        LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));
        if(DataCurrentListEntry->DllBase == LargestPossibleAddress){
            return DataCurrentListEntry;
        }
        CurrentEntry = CurrentEntry->Flink;
    }
    return NULL;
}

BOOL CheckForInlineHook(BYTE *CheckAddress){

    // This function checks the first byte of a function to search for jumps.
    // 0xEB = Short Jump
    // 0xE9 = Near Jump
    // 0xFF = ModR/M Jump
    if(*CheckAddress == 0xeb || *CheckAddress == 0xe9 || *CheckAddress == 0xff){
        return TRUE;
    } else {
        return FALSE;
    }
}

BOOL DetermineJump(BYTE *JumpSource){

    // This function is called after discovering an inline function hook and it calculates the address the hook jumps to.
    // This address can be used to determine what module the jump lands in.
    // If the jump lands in an external module, that's a hook and an opportunity will be presented to unhook it if the argument is specified.

    // If a jump is determined to be a hook, this function is called recursively to follow the jumps through trampolines to their end destination.
    static BOOL RecursiveCall         = FALSE;
    static BOOL FollowingExternalJump = FALSE;

    BOOL ExternalJump   = FALSE;
    BOOL InlineUnhooked = FALSE;

    int  ByteAmount = 0;

    switch(*JumpSource){
        // EB XX -> Jumps to a destination within a short range from the current instruction, XX representing a signed 8-bit offset.
        case 0xeb:
            ByteAmount = 1; // 0xeb *XX*
            break;

        // E9 XX XX XX XX -> Jumps to a destination within a larger range than a short jump, XX representing a signed 32-bit offset.
        case 0xe9:
            ByteAmount = 4; // 0xe9 *XX XX XX XX*
            break;

        // FF -> Far more complicated, I still don't understand it, luckily 0xFF25 shows up almost exclusively.
        // Consult AMD64 Arch Programmer's Module: https://www.amd.com/system/files/TechDocs/40332.pdf - Page 1284.
        case 0xff:
            unsigned char modRM = *(JumpSource + 1);         // Accessing the ModR/M byte after 0xFF
            unsigned char mod   = (modRM >> 6) & 0b00000011; // Bit 7, 6
            unsigned char reg   = (modRM >> 3) & 0b00000111; // Bit 5, 4, 3
            unsigned char rm    =  modRM       & 0b00000111; // Bit 2, 1, 0
            if(mod == 0b00000000 && rm == 0b00000101){       // 0xFF25 is *very* common if not exclusively present
                ByteAmount = 5; // 0xff *XX YY YY YY YY* (XX == ModRM byte, YY == signed 32-bit displacement)
            } else {
                if(modRM != 0xff){
                    // 0xff is an invalid ModRM byte meaning it isn't actually a jump.
                    if(ARG_VERBOSE){
                        printf("[!] PANIC: ModRM byte jumps are hard.\n");
                    }
                }
                return FALSE;
            }
            break;
    }

    // This byte array will hold the offset used by the jump
    char RawBytes[8] = { 0x00 };

    // Verifies that this is in fact a jump Valkyrie knows how to work with.
    if(ByteAmount){
        if(*JumpSource == 0xff){
            JumpSource += 2;
            for(int i = 0; i < ByteAmount - 1 && i < sizeof(RawBytes); i++){ // ByteAmount - 1: ModR/M byte not used for JumpOffset.
                RawBytes[i] = *JumpSource;
                JumpSource++;
            }
        } else {
            JumpSource++;
            for(int i = 0; i < ByteAmount && i < sizeof(RawBytes); i++){
                RawBytes[i] = *JumpSource;
                JumpSource++;
            }
        }

        JumpSource -= ByteAmount + 1; // Restore original address

        signed int *JumpOffset = (void *)RawBytes;
        void *JumpDestination = JumpSource + *JumpOffset + ByteAmount + 1;

        LDR_DATA_TABLE_ENTRY *JumpSourceModule      = DetermineModule(JumpSource);
        LDR_DATA_TABLE_ENTRY *JumpDestinationModule = DetermineModule(JumpDestination);

        // Reserved4 is the BaseDllName, for some reason undocumented in Winternl.h
        // https://www.vergiliusproject.com/kernels/x64/Windows%2011/21H2%20(RTM)/_LDR_DATA_TABLE_ENTRY
        UNICODE_STRING *JumpSourceModuleName      = (UNICODE_STRING *)JumpSourceModule->Reserved4;
        UNICODE_STRING *JumpDestinationModuleName = (UNICODE_STRING *)JumpDestinationModule->Reserved4;

        // This checks if the jump originated and landed within the same module.
        // Generally this isn't a big deal, internal jumps happen legitimately in many Windows functions.
        // However, internal jumps that originate from external jumps are possible and need to be accounted for.
        // Ex. Internal Module A -> External Module B -> External Module B. 
        if(strcmp((const char *)JumpSourceModule->FullDllName.Buffer, (const char *)JumpDestinationModule->FullDllName.Buffer) == 0){
            ExternalJump = FALSE;

            // If the current call to this function isn't recursive, it is the first time this particular jump (potentially jump chain) is being encountered.
            // This is important to ensure clean terminal output. We only want to report a new jump once, not every jump that follows it.
            // Internal jumps aren't worth reporting unless verbosity is specified.
            if(ARG_VERBOSE && !RecursiveCall){
                char *JumpSourceFunctionName = GetFunctionName(JumpSourceModule->DllBase, JumpSource);
                wprintf(L"[Inline Check] %ls!%hs\n", JumpSourceModuleName->Buffer, JumpSourceFunctionName);
                printf("[*] INTERNAL: Likely NOT a hook.\n");
            }

            // If the current call to this function is recursive, it's not worth reporting UNLESS you arrived here from following an external jump.
            // The recursive nature also means the original message above reporting the jump has already been reported, this is simply following up on the chain.
            if(ARG_VERBOSE && !FollowingExternalJump){
                if(CheckForInlineHook(JumpDestination) == FALSE){
                    wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
                } else {
                    wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
                    
                    // If another jump is discovered, the function is called recursively to see where this new jump goes.
                    RecursiveCall = TRUE;
                    DetermineJump(JumpDestination);
                }
            }

            // External jumps are worth following and reporting as output regardless of verbosity.
            if(FollowingExternalJump){

                // If there's no more jumps at the destination of this external jump, that needs to be specified because FollowingExternalJump is static.
                if(CheckForInlineHook(JumpDestination) == FALSE){
                    FollowingExternalJump = FALSE;

                    if(ARG_UNHOOK){
                        wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
                    } else {
                        wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
                    }
                } else {
                    wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
                    
                    RecursiveCall = TRUE;
                    DetermineJump(JumpDestination);
                }
            }
        }

        // This checks to see if the jump originates and lands in different modules. This is a likely indicator of a hook.
        if(strcmp((const char *)JumpSourceModule->FullDllName.Buffer, (const char *)JumpDestinationModule->FullDllName.Buffer) != 0){
            ExternalJump = TRUE;

            if(!RecursiveCall){
                char *JumpSourceFunctionName = GetFunctionName(JumpSourceModule->DllBase, JumpSource);
                wprintf(L"[Inline Check] %ls!%hs\n", JumpSourceModuleName->Buffer, JumpSourceFunctionName);
                printf("[!] EXTERNAL: Likely a hook.\n");
            }

            if(CheckForInlineHook(JumpDestination) == FALSE){
                wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
            } else {
                wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
                    
                RecursiveCall = TRUE;
                FollowingExternalJump = TRUE;
                DetermineJump(JumpDestination);
            }
        }
        
        // During unhooking, we only need to unhook the jump placed directly on the function to restore it.
        // We don't care about unhooking every potential succeeding jump in the hook such as trampolines, just the hook itself.
        if(ARG_UNHOOK && ExternalJump == TRUE && RecursiveCall == FALSE){
            printf("[+] Attempting unhooking...\n");
            InlineUnhooked = UnhookInline((void *)JumpSource, JumpSourceModule);
            if(InlineUnhooked){
                printf("[+] Unhooked!\n\n");
            }
        }

        // RecursiveCall is static to persist across calls in the event of recursive calls, needs to be unset before leaving.
        RecursiveCall = FALSE;

        return ExternalJump;
    } else {
        return ExternalJump;
    } 
}


BOOL CheckForIATHook(HMODULE BaseAddress, char *cmpFunctionName, void **cmpFunctionAddress){

    // This function compares addresses taken from the process' Import Address Table (IAT) against the address taken from the module's Export Address Table (EAT).
    // If they aren't the same address, the IAT is hooked and the function will eventually return TRUE.
    // If the unhook argument is specified, the address in the IAT will be overwritten with the correct one from the EAT.

    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *ntHeader  = (IMAGE_NT_HEADERS *)(dosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);

    DWORD *EAT             = (DWORD *)(ExportDirectory->AddressOfFunctions    + (BYTE *)BaseAddress);
    DWORD *FunctionName    = (DWORD *)(ExportDirectory->AddressOfNames        + (BYTE *)BaseAddress);
    WORD  *FunctionOrdinal = (WORD  *)(ExportDirectory->AddressOfNameOrdinals + (BYTE *)BaseAddress);

    for(int i = 0; i < ExportDirectory->NumberOfNames; i++){
        char *CurrentFunctionName = (char *)(FunctionName[i] + (BYTE *)BaseAddress);

        // Function from the IAT has been found in the module's EAT
        if(strcmp(CurrentFunctionName, cmpFunctionName) == 0){
            void *FunctionAddress = (void *)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);
            if(FunctionAddress == *cmpFunctionAddress){;
                return FALSE;
            } else {
                printf("[IAT Check] %s!%s\n", ExportDirectory->Name + (BYTE *)BaseAddress, CurrentFunctionName);
                printf("[!] Hook found!\n", CurrentFunctionName);
                if(ARG_UNHOOK){
                    printf("[+] Attempting to unhook IAT entry from %p to %p\n", *cmpFunctionAddress, FunctionAddress);
                    *cmpFunctionAddress = FunctionAddress;
                    printf("[+] Unhooked!\n\n");
                }
                return TRUE;
            }
        }
    }

    // Forwarder Functions
    for(int i = 0; i < ExportDirectory->NumberOfNames; i++){
        void *FunctionAddress = (void *)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);
        if(FunctionAddress == *cmpFunctionAddress){
            char *ForwardedName = (char *)(FunctionName[i] + (BYTE *)BaseAddress);
            if(ARG_VERBOSE){
                printf("[*] Forwarder Resolution: %s -> %s\n\n", cmpFunctionName, ForwardedName);
            }
            return FALSE;
        }
    }

    // Something has gone very wrong if we get this far.
    return TRUE;
}

void ScanImportedFunctions(HMODULE BaseAddress){

    // This function parses the process' Import Address Table (IAT) to check for both IAT hooks and inline hooks in imported functions.

    BOOL IATHooked    = FALSE;
    BOOL InlineHooked = FALSE;

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_IMPORT_DESCRIPTOR *ImportDirectory = (IMAGE_IMPORT_DESCRIPTOR *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (BYTE *)BaseAddress);

    while(ImportDirectory->Name != 0){
        IMAGE_THUNK_DATA *ILT = (IMAGE_THUNK_DATA *)(ImportDirectory->OriginalFirstThunk + (BYTE *)BaseAddress);
        IMAGE_THUNK_DATA *IAT = (IMAGE_THUNK_DATA *)(ImportDirectory->FirstThunk         + (BYTE *)BaseAddress);

        char *ModuleName = ImportDirectory->Name + (BYTE *)BaseAddress;

        while(IAT->u1.Function != 0){
            ULONGLONG ILT_ImportByNameRVA = ILT->u1.AddressOfData;
            ULONGLONG IAT_FunctionAddress = IAT->u1.Function;

            IMAGE_IMPORT_BY_NAME *ImportByName = (IMAGE_IMPORT_BY_NAME *)(ILT_ImportByNameRVA + (BYTE *)BaseAddress);
            LDR_DATA_TABLE_ENTRY *Module = DetermineModule((void *)IAT_FunctionAddress); // Bad way to do it, kills forwarded functions.         

            IATHooked = CheckForIATHook(Module->DllBase, ImportByName->Name, (void *)&IAT_FunctionAddress);
            
            // Handled by Aggressive()
            if(!ARG_AGGRESSIVE){
                InlineHooked = CheckForInlineHook((BYTE *)IAT_FunctionAddress);
            }

            if(InlineHooked){
                DetermineJump((BYTE *)IAT_FunctionAddress);
            }
            IAT++;
            ILT++;
        }
        ImportDirectory++;
    }
}

void Aggressive(){

    // This function is only called if the Aggressive argument is specified.
    // Every single loaded module is sent to ScanModuleFunctions to scan every exported function from that module where they are checked for inline hooks.

    PEB *ProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Loader = (PEB_LDR_DATA *)ProcessEnvironmentBlock->Ldr;
    LIST_ENTRY *ModuleList = &Loader->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentEntry = ModuleList->Flink->Flink;

    while(CurrentEntry != ModuleList){
        LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));
        ScanModuleFunctions((HMODULE)DataCurrentListEntry->DllBase);
        CurrentEntry = CurrentEntry->Flink;
    }
}

void Banner(){
    printf("\n");
    printf("      \\\\                     //\n");
    printf("       \\\\                   //\n");
    printf("        \\\\ V A L K Y R I E //\n");
    printf("         \\\\               //\n");
    printf("          \\\\             //\n");
    printf("Usage:\n");
    printf("-h   Display this banner.\n");
    printf("-a   Parse every loaded module's functions for inline hooks.\n");
    printf("-s   Scan for both IAT hooks and inline hooks.\n");
    printf("-u   Unhook detected hooks.\n");
    printf("-v   Verbose output.\n");
}

int main(int argc, char *argv[]){

// Arguments should only be parsed if Valkyrie is compiled as an executable.
#ifndef DLL_BUILD
    if(argc != 1){
        for(int i = 1; i < argc; i++){
            switch(argv[i][0]){
                case '-':
                    switch(argv[i][1]){
                        case 'h':
                            Banner();
                            return 0;
                        case 'a':
                            ARG_AGGRESSIVE = TRUE;
                            break;
                        case 's':
                            ARG_SCAN = TRUE;
                            break;
                        case 'u':
                            ARG_SCAN   = TRUE;
                            ARG_UNHOOK = TRUE;
                            break;
                        case 'v':
                            ARG_VERBOSE = TRUE;
                            break;
                        default:
                            Banner();
                            return -1;
                    }
            }
        }
    } else {
        Banner();
        return -1;
    }
#endif

    printf("\n");
    printf("      \\\\                     //\n");
    printf("       \\\\                   //\n");
    printf("        \\\\ V A L K Y R I E //\n");
    printf("         \\\\               //\n");
    printf("          \\\\             //\n");

    HMODULE BaseAddress = CustomGetModuleHandle(NULL);

    if(ARG_SCAN && !ARG_AGGRESSIVE){
        printf("\n[+] Scanning imported functions for both inline and IAT hooks...\n\n");
        ScanImportedFunctions(BaseAddress);
        printf("[+] Finished scanning imported functions.\n");
    }

    if(ARG_AGGRESSIVE){
        printf("\n[+] Scanning imported functions for IAT hooks...\n\n");
        ScanImportedFunctions(BaseAddress);
        printf("[+] Finished scanning for IAT hooks.\n\n");
        printf("[+] Scanning every function in every loaded module for inline hooks.\n\n");
        Aggressive();
        printf("[+] Finished scanning every loaded module for inline hooks.\n");
    }
}


// Arguments have to be specified while building as a DLL.
#ifdef DLL_BUILD
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ){
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            #ifdef scan
            ARG_SCAN   = TRUE;
            #endif
            #ifdef unhook
            ARG_SCAN   = TRUE;
            ARG_UNHOOK = TRUE;
            #endif
            #ifdef aggressive
            ARG_AGGRESSIVE = TRUE;
            #endif
            #ifdef verbose
            ARG_VERBOSE = TRUE;
            #endif
            main(NULL, NULL);
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            if (lpvReserved != NULL)
            {
                break;
            }
            break;
    }
    return TRUE;
}
#endif