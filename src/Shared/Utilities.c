#include "..\Shared\Valkyrie.h"

// Walk the Export Address Table of the BaseAddress, return the address of the HashedFunctionName
FARPROC CustomGetProcAddress(HMODULE BaseAddress, ULONG HashedFunctionName){
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);

    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);

    DWORD *EAT             = (DWORD *)(ExportDirectory->AddressOfFunctions    + (BYTE *)BaseAddress);
    DWORD *FunctionName    = (DWORD *)(ExportDirectory->AddressOfNames        + (BYTE *)BaseAddress);
    WORD  *FunctionOrdinal = (WORD  *)(ExportDirectory->AddressOfNameOrdinals + (BYTE *)BaseAddress);

    for(DWORD i = 0; i < ExportDirectory->NumberOfNames; i++){
        CHAR *CurrentFunctionName = (CHAR *)(FunctionName[i] + (BYTE *)BaseAddress);
        if(HashDjb2A(CurrentFunctionName) == HashedFunctionName){
            VOID *FunctionAddress = (VOID *)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);
            return (FARPROC)FunctionAddress;
        }
    }
    return NULL;
}

// Check for '.' in FunctionAddress, indicating a forwader string
BOOL IsForwarder(CHAR *FunctionAddress){
    if(strchr(FunctionAddress, '.')){
        return TRUE;
    } else {
        return FALSE;
    }
}

// Returns the function address of the forwarder string's corresponding function
FARPROC ProcessForwarder(CHAR *FunctionAddress){
    HMODULE ForwarderDLL = NULL;
    CHAR ForwarderDLLName[128] = { 0 };
    CHAR ForwarderDLLEnd[5] = { '.', 'd', 'l', 'l', '\0' };
    CHAR ForwarderFunctionName[128] = { 0 };

    DWORD ForwarderDot = strchr(FunctionAddress, '.') - FunctionAddress;

    memcpy((VOID *)ForwarderDLLName, (VOID *)FunctionAddress, ForwarderDot);
    memcpy((VOID *)(ForwarderDLLName + ForwarderDot), (VOID *)ForwarderDLLEnd, sizeof(ForwarderDLLEnd));
    memcpy((VOID *)ForwarderFunctionName, (VOID *)(FunctionAddress + ForwarderDot + 1), strlen((const char *)(FunctionAddress + ForwarderDot + 1)));

    if(!GetLoadedModule(ForwarderDLLName)){
        return 0;
    }

    return GetProcAddress(CustomGetModuleHandle(ForwarderDLLName), ForwarderFunctionName);
}

// Walk the PEB, return the base address of the loaded module whose hashed name is ModuleHash
HMODULE CustomGetModuleHandleHash(ULONG ModuleHash){
    PEB *ProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Loader = (PEB_LDR_DATA *)ProcessEnvironmentBlock->Ldr;
    LIST_ENTRY *ModuleList = &Loader->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentEntry = ModuleList->Flink;


    // If 0 - return process base
    if(!ModuleHash){
        LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));
        return (HMODULE)DataCurrentListEntry->DllBase;
    } else {
        while(CurrentEntry != ModuleList){
            LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));

            // Reserved4 is BaseDllName - module name without the path
            // https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/_LDR_DATA_TABLE_ENTRY
            UNICODE_STRING *BaseDllName = (UNICODE_STRING *)DataCurrentListEntry->Reserved4;

            if(HashDjb2W(BaseDllName->Buffer) == ModuleHash){
                return (HMODULE)DataCurrentListEntry->DllBase; 
            }

            CurrentEntry = CurrentEntry->Flink;
        }
        return NULL;
    }
}

// Walk the PEB, return the base address of the loaded module named ModuleName
HMODULE CustomGetModuleHandle(CHAR *ModuleName){
    PEB *ProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Loader = (PEB_LDR_DATA *)ProcessEnvironmentBlock->Ldr;
    LIST_ENTRY *ModuleList = &Loader->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentEntry = ModuleList->Flink;

    WCHAR WideModuleName[VALKYRIE_MAX_STRING_LENGTH];
    ANSIToWide(ModuleName, WideModuleName, VALKYRIE_MAX_STRING_LENGTH * sizeof(WCHAR));

    while(CurrentEntry != ModuleList){
        LDR_DATA_TABLE_ENTRY *DataCurrentListEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));

        // Reserved4 is BaseDllName - module name without the path
        // https://www.vergiliusproject.com/kernels/x64/Windows%2011/22H2%20(2022%20Update)/_LDR_DATA_TABLE_ENTRY
        UNICODE_STRING *BaseDllName = (UNICODE_STRING *)DataCurrentListEntry->Reserved4;

        if(CompareWideStrings(BaseDllName->Buffer, WideModuleName)){
            return (HMODULE)DataCurrentListEntry->DllBase; 
        }
            CurrentEntry = CurrentEntry->Flink;
    }
        return NULL;
}

// Check if Pointer points to valid allocated memory
BOOL ProbeForValidMemory(VOID *Pointer){
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID SysAddr_NtQueryVirtualMemory = (LPVOID)((BYTE *)CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_NTDLL), HASH_FUNC_NTQUERYVIRTUALMEMORY) + 0x12);

    NTSTATUS Status = Sys_NtQueryVirtualMemory((HANDLE)-1, (PVOID)Pointer, 0, (PVOID)&mbi, sizeof(mbi), NULL, SysAddr_NtQueryVirtualMemory);
    
    if(NT_SUCCESS(Status)){
        if(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)){
            return TRUE;
        }
    }

    return FALSE;
}

// Returns the name of the function at FunctionAddress inside the module.
CHAR *GetFunctionName(HMODULE BaseAddress, VOID *FunctionAddress){
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);

    DWORD *EAT             = (DWORD *)(ExportDirectory->AddressOfFunctions    + (BYTE *)BaseAddress);
    DWORD *FunctionName    = (DWORD *)(ExportDirectory->AddressOfNames        + (BYTE *)BaseAddress);
    WORD  *FunctionOrdinal = (WORD  *)(ExportDirectory->AddressOfNameOrdinals + (BYTE *)BaseAddress);

    for(DWORD i = 0; i < ExportDirectory->NumberOfNames; i++){
        CHAR *CurrentFunctionName    = (CHAR *)(FunctionName[i] + (BYTE *)BaseAddress);
        VOID *CurrentFunctionAddress = (VOID *)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);

        if(CurrentFunctionAddress == FunctionAddress){
            return CurrentFunctionName;
        }
    }
    return NULL;
}

// Returns a LOADED_MODULE_LIST * containing all loaded modules pulled from the PEB
LOADED_MODULE_LIST *GetLoadedModules(){
    // Static loaded module list prevents sequential PEB walks
    static LOADED_MODULE_LIST *LoadedModuleList;
    
    if(LoadedModuleList){
        return LoadedModuleList;
    }

    LoadedModuleList = (LOADED_MODULE_LIST *)malloc(sizeof(LOADED_MODULE_LIST));

    PEB *ProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);
    PEB_LDR_DATA *Loader = (PEB_LDR_DATA *)ProcessEnvironmentBlock->Ldr;
    LIST_ENTRY *ModuleList = &Loader->InMemoryOrderModuleList;
    LIST_ENTRY *CurrentEntry = ModuleList->Flink;
    LoadedModuleList->ModuleCount = 0;

    while(CurrentEntry != ModuleList){
        LoadedModuleList->ModuleCount++;
        CurrentEntry = CurrentEntry->Flink;
    }

    LoadedModuleList->LoadedModules = (LDR_DATA_TABLE_ENTRY **)malloc(sizeof(LDR_DATA_TABLE_ENTRY *) * LoadedModuleList->ModuleCount);
    CurrentEntry = ModuleList->Flink;

    for(DWORD i = 0; i < LoadedModuleList->ModuleCount; i++){
        LoadedModuleList->LoadedModules[i] = (LDR_DATA_TABLE_ENTRY *)((BYTE *)CurrentEntry - sizeof(LIST_ENTRY));
        CurrentEntry = CurrentEntry->Flink;
    }

    return LoadedModuleList;
}

// Returns the LDR_DATA_TABLE_ENTRY struct of the loaded module named ModuleName
LDR_DATA_TABLE_ENTRY *GetLoadedModule(CHAR *ModuleName){
    LOADED_MODULE_LIST *LoadedModuleList = GetLoadedModules();

    // Turn the ANSI string to Unicode
    DWORD Length = MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, NULL, 0);
    WCHAR *CheckWModuleName = (WCHAR *)malloc(Length * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, ModuleName, -1, CheckWModuleName, Length);

    for(DWORD i = 0; i < LoadedModuleList->ModuleCount; i++){
        LDR_DATA_TABLE_ENTRY *CurrentLoadedModule = LoadedModuleList->LoadedModules[i];
        WCHAR *CurrentModuleName = ((UNICODE_STRING *)CurrentLoadedModule->Reserved4)->Buffer;

        if(CompareStringW(LOCALE_USER_DEFAULT, NORM_IGNORECASE, CurrentModuleName, -1, CheckWModuleName, -1) == 2){

            free(CheckWModuleName);
            CheckWModuleName = NULL;

            return LoadedModuleList->LoadedModules[i];
        }
    }

    free(CheckWModuleName);
    CheckWModuleName = NULL;

    return NULL;
}

// Returns the LDR_DATA_TABLE_ENTRY struct of the module that contains CheckAddress in its address space
LDR_DATA_TABLE_ENTRY *DetermineModule(VOID *CheckAddress){
    LOADED_MODULE_LIST *LoadedModuleList = GetLoadedModules();

    for(DWORD i = 0; i < LoadedModuleList->ModuleCount; i++){
        IMAGE_DOS_HEADER *TestDosHeader = (IMAGE_DOS_HEADER *)LoadedModuleList->LoadedModules[i]->DllBase;
        IMAGE_NT_HEADERS *TestNtHeader = (IMAGE_NT_HEADERS *)((BYTE *)LoadedModuleList->LoadedModules[i]->DllBase + TestDosHeader->e_lfanew);

        if((ULONGLONG)CheckAddress > (ULONGLONG)LoadedModuleList->LoadedModules[i]->DllBase && (ULONGLONG)CheckAddress < (ULONGLONG)((ULONGLONG)LoadedModuleList->LoadedModules[i]->DllBase + TestNtHeader->OptionalHeader.SizeOfImage)){
            return LoadedModuleList->LoadedModules[i];
        }
    }

    return NULL;
}

// Loader friendly - converts ANSIString into a wide string in WideBuffer, returns TRUE if successful, FALSE if not
BOOL ANSIToWide(CHAR *ANSIString, WCHAR *WideBuffer, DWORD WideBufferSize){
    if(!ANSIString || !WideBuffer || !WideBufferSize){
        return FALSE;
    }

    DWORD ANSIStringLength = 0;

    while(*(ANSIString + ANSIStringLength) != 0){
        ANSIStringLength++;
    }

    if(WideBufferSize < (ANSIStringLength + 1)){
        return FALSE;
    }

    for(DWORD i = 0; i < ANSIStringLength; i++){
        WideBuffer[i] = ANSIString[i];
    }
    WideBuffer[ANSIStringLength] = L'\0';
    return TRUE;
}

// Loader friendly - compares two wide strings, returns TRUE if they match, FALSE if they don't
BOOL CompareWideStrings(WCHAR *String1, WCHAR *String2){
    if(!String1 || !String2){
        return FALSE;
    }

    DWORD Iterator = 0;
    WCHAR Character1;
    WCHAR Character2;

    while(String1[Iterator] != L'\0' && String2[Iterator] != L'\0'){
        Character1 = ToLowerWide(String1[Iterator]);
        Character2 = ToLowerWide(String2[Iterator]);

        if(Character1 != Character2){
            return FALSE;
        }
        Iterator++;
    }

    if(String1[Iterator] == '\0' && String2[Iterator] == '\0'){
        return TRUE;
    }

    return FALSE;
}

// Loader friendly - returns lowercase Character
WCHAR ToLowerWide(WCHAR Character){
    if(Character >= L'A' && Character <= L'Z'){
        return Character + (L'a' - L'A');
    }
    return Character;
}

// Loader friendly - converts WideString into an ANSI string in ANSIBuffer, returns TRUE if successful, FALSE if not
BOOL WideToANSI(WCHAR *WideString, CHAR *ANSIBuffer, DWORD ANSIBufferSize){
   if(!WideString || !ANSIBuffer || !ANSIBufferSize){
       return FALSE;
   }

   DWORD WideStringLength = 0;

   while(*(WideString + WideStringLength) != L'\0'){
       WideStringLength++;
   }

   if(ANSIBufferSize < (WideStringLength + 1)){
       return FALSE;
   }

   for(DWORD i = 0; i < WideStringLength; i++){
       ANSIBuffer[i] = (CHAR)WideString[i];
   }
   ANSIBuffer[WideStringLength] = '\0';
   return TRUE;
}