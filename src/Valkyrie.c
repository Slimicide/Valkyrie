#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

// TODO:
// Do better testing on IAT hooks, ensure you can actually hook the IAT, not just simulate it.
// Need a stealthy means of calling VirtualProtect AND need to ensure VirtualProtect is NOT hooked.
// Find out what the 0xc00 is.

// REFERENCES
// ----------
// Sektor7
// https://www.amd.com/system/files/TechDocs/40332.pdf
// https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)

BOOL ARG_SCAN       = FALSE;
BOOL ARG_UNHOOK     = FALSE;
BOOL ARG_VERBOSE    = FALSE;
BOOL ARG_AGGRESSIVE = FALSE;

void ScanModuleFunctions(HMODULE BaseAddress){
    static BOOL init = TRUE;
    static char **ScannedModules = NULL;
    int ModuleCount = 20; // This is only an initial value.

    if(init){
        ScannedModules = calloc(ModuleCount, sizeof(char *));
        init = FALSE;
    }

    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *ntHeader  = (IMAGE_NT_HEADERS *)(dosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);
    char *ModuleName = ExportDirectory->Name + (BYTE *)BaseAddress;

    if(ScannedModules){
        for(int i = 0; i < ModuleCount; i++){
            if(ScannedModules[i]){
                if(strcmp(ScannedModules[i], ModuleName) == 0){
                    return;
                }
            }
        }

        if(ScannedModules[ModuleCount - 1] != NULL){
            char **tmpScannedModules = calloc(ModuleCount, sizeof(char *));
            for(int i = 0; i < ModuleCount; i++){
                tmpScannedModules[i] = ScannedModules[i];
            }
            free(ScannedModules);
            ScannedModules = NULL;

            ModuleCount += 10;

            ScannedModules = calloc(ModuleCount, sizeof(char *));
            for(int i = 0; i < ModuleCount - 10; i++){
                ScannedModules[i] = tmpScannedModules[i];
            }
            free(tmpScannedModules);
            tmpScannedModules = NULL;
        }

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

    for(int i = 0; i < ExportDirectory->NumberOfNames; i++){
        void *CheckAddress = (void *)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);
        if(CheckForInlineHook(CheckAddress)){
            DetermineJump((BYTE *)CheckAddress);
        }
    }
    return;
}

BOOL UnhookInline(void *UnhookAddress, LDR_DATA_TABLE_ENTRY *Module){
    FILE *CleanModule = NULL;
    DWORD OldProtect = 0;
    DWORD UnhookIncrement = 0;
    DWORD Offset = (BYTE *)UnhookAddress - (BYTE *)Module->DllBase - 0xc00; // Why minus 0xc00? Who knows, but it works!

    CleanModule = _wfopen(Module->FullDllName.Buffer, L"rb");
    if(!CleanModule){
        wprintf(L"[!] Unhooking: Failed to open %ls.\n", Module->FullDllName.Buffer);
        return FALSE;
    }
    if(fseek(CleanModule, Offset, SEEK_SET) != 0){
        wprintf(L"[!] Unhooking: Failed to jump to function offset in %ls.\n", Module->FullDllName.Buffer);
    }

    unsigned char cleanBuffer[8];
    fread(cleanBuffer, sizeof(cleanBuffer), 1, CleanModule);

    if(VirtualProtect(UnhookAddress, 4096, PAGE_EXECUTE_READWRITE, &OldProtect)){
        while(*(LONGLONG *)UnhookAddress != *(LONGLONG *)cleanBuffer){
            for(int i = 0; i < sizeof(cleanBuffer); i++){
                *(BYTE *)UnhookAddress = cleanBuffer[i];
                (BYTE *)UnhookAddress += 1;
                UnhookIncrement += 1;
            }
            fread(cleanBuffer, sizeof(cleanBuffer), 1, CleanModule);   
        }
        fclose(CleanModule);
        (BYTE *)UnhookAddress -= UnhookIncrement;
        VirtualProtect(UnhookAddress, 4096, OldProtect, &OldProtect);
        return TRUE;
    } else {
        wprintf(L"[!] Unhooking: Failed to modify %ls page permissions.\n", Module->FullDllName.Buffer);
        return FALSE;
    }
}

HMODULE CustomGetModuleHandle(char *ModuleName){
    PEB *ProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Loader = (PEB_LDR_DATA *)ProcessEnvironmentBlock->Ldr;
    LIST_ENTRY *ModuleList = &Loader->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentEntry = ModuleList->Flink;

    if(ModuleName == NULL){
        LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));
        return (HMODULE)DataCurrentListEntry->DllBase;
    } else {

        WCHAR WideModuleName[256];
        size_t len = mbstowcs(WideModuleName, ModuleName, sizeof(WideModuleName) / sizeof(WCHAR));

        while(CurrentEntry != ModuleList){
            LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));
            UNICODE_STRING *BaseDllName = (UNICODE_STRING *)DataCurrentListEntry->Reserved4;

            size_t DllNameLen = wcslen(BaseDllName->Buffer);
            WCHAR *cmpDllName = malloc(DllNameLen * sizeof(WCHAR));
            wcscpy_s(cmpDllName, DllNameLen * sizeof(WORD), BaseDllName->Buffer);

            if(wcscmp(_wcslwr(cmpDllName), _wcslwr(WideModuleName)) == 0){
                return (HMODULE)DataCurrentListEntry->DllBase; 
            }
            CurrentEntry = CurrentEntry->Flink;
            
            free(cmpDllName);
            cmpDllName = NULL;
        }
        return NULL;
    }
}

char *GetFunctionName(HMODULE BaseAddress, void *ProcAddress){
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *ntHeader  = (IMAGE_NT_HEADERS *)(dosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);

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

LDR_DATA_TABLE_ENTRY* DetermineModule(void *CheckAddress){

    // NOTE: DetermineModule returns the highest possible module *based on those present in InMemoryOrderModuleList.
    
    PEB *ProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Loader = (PEB_LDR_DATA *)ProcessEnvironmentBlock->Ldr;
    LIST_ENTRY *ModuleList = &Loader->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentEntry = ModuleList->Flink;

    void *LargestPossibleAddress  = 0x0000000000000000;

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
    if(*CheckAddress == 0xeb || *CheckAddress == 0xe9 || *CheckAddress == 0xff){
        return TRUE;
    } else {
        return FALSE;
    }
}

BOOL DetermineJump(BYTE *JumpSource){
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

        case 0xff:
            unsigned char modRM = *(JumpSource + 1);         // Accessing the ModR/M byte after 0xFF
            unsigned char mod   = (modRM >> 6) & 0b00000011; // Bit 7, 6
            unsigned char reg   = (modRM >> 3) & 0b00000111; // Bit 5, 4, 3
            unsigned char rm    =  modRM       & 0b00000111; // Bit 2, 1, 0
            if(mod == 0b00000000 && rm == 0b00000101){ // 0xFF25 is *very* common if not exclusively present
                ByteAmount = 5; // 0xff *XX YY YY YY YY* (XX == ModRM byte, YY == signed 32-bit displacement)
            } else {
                if(modRM != 0xff){
                    // 0xff is an invalid ModRM byte meaning it isn't actually a jump.
                    printf("[!] PANIC: ModRM byte jumps are hard.\n");
                }
                return FALSE;
            }
            break;
    }

    char RawBytes[8] = { 0x00 };

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


        // Unhooked Windows functions occassionally have jumps to other spots within the same module, likely not a hook.
        if(strcmp((const char *)JumpSourceModule->FullDllName.Buffer, (const char *)JumpDestinationModule->FullDllName.Buffer) == 0){
            ExternalJump = FALSE;

            if(ARG_VERBOSE && !RecursiveCall){
                char *JumpSourceFunctionName = GetFunctionName(JumpSourceModule->DllBase, JumpSource);
                wprintf(L"[Inline Check] %ls!%hs\n", JumpSourceModuleName->Buffer, JumpSourceFunctionName);
                printf("[*] INTERNAL: Likely NOT a hook.\n");
            }

            if(ARG_VERBOSE && !FollowingExternalJump){
                if(CheckForInlineHook(JumpDestination) == FALSE){
                    wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
                } else {
                    wprintf(L"\t[%ls] 0x%p -> 0x%p [%ls]\n", JumpSourceModule->FullDllName.Buffer, JumpSource, JumpDestination, JumpDestinationModule->FullDllName.Buffer);
                    
                    RecursiveCall = TRUE;
                    DetermineJump(JumpDestination);
                }
            }

            if(FollowingExternalJump){
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
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *ntHeader  = (IMAGE_NT_HEADERS *)(dosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);

    DWORD *EAT             = (DWORD *)(ExportDirectory->AddressOfFunctions    + (BYTE *)BaseAddress);
    DWORD *FunctionName    = (DWORD *)(ExportDirectory->AddressOfNames        + (BYTE *)BaseAddress);
    WORD  *FunctionOrdinal = (WORD  *)(ExportDirectory->AddressOfNameOrdinals + (BYTE *)BaseAddress);

    for(int i = 0; i < ExportDirectory->NumberOfNames; i++){
        char *CurrentFunctionName = (char *)(FunctionName[i] + (BYTE *)BaseAddress);

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
    BOOL IATHooked    = FALSE;
    BOOL InlineHooked = FALSE;

    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *ntHeader  = (IMAGE_NT_HEADERS *)(dosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_IMPORT_DESCRIPTOR *ImportDirectory = (IMAGE_IMPORT_DESCRIPTOR *)(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (BYTE *)BaseAddress);

    while(ImportDirectory->Name != 0){
        IMAGE_THUNK_DATA *ILT = (IMAGE_THUNK_DATA *)(ImportDirectory->OriginalFirstThunk + (BYTE *)BaseAddress);
        IMAGE_THUNK_DATA *IAT = (IMAGE_THUNK_DATA *)(ImportDirectory->FirstThunk         + (BYTE *)BaseAddress);

        char *ModuleName = ImportDirectory->Name + (BYTE *)BaseAddress;

        while(IAT->u1.Function != 0){
            ULONGLONG ILT_ImportByNameRVA = ILT->u1.AddressOfData;
            ULONGLONG IAT_FunctionAddress = IAT->u1.Function;

            IMAGE_IMPORT_BY_NAME *ImportByName = (IMAGE_IMPORT_BY_NAME *)(ILT_ImportByNameRVA + (BYTE *)BaseAddress);
            LDR_DATA_TABLE_ENTRY *Module = DetermineModule((void *)IAT_FunctionAddress); // Bad way to do it, kills forwarded functions.         

            IATHooked    = CheckForIATHook(Module->DllBase, ImportByName->Name, (void *)&IAT_FunctionAddress);
            
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
    printf("\n");
    printf("      \\\\                     //\n");
    printf("       \\\\                   //\n");
    printf("        \\\\ V A L K Y R I E //\n");
    printf("         \\\\               //\n");
    printf("          \\\\             //\n");

    HMODULE BaseAddress = CustomGetModuleHandle(NULL);

    if(ARG_SCAN){
        printf("\n[+] Scanning imported functions for both inline and IAT hooks...\n\n");
        ScanImportedFunctions(BaseAddress);
        printf("[+] Finished scanning imported functions.\n\n");
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
