#include "Valkyrie.h"

// Returns the address of the embedded LdrValkyrie.dll in Valkyrie.exe's .rdata section
LPVOID FindEmbeddedModule(HMODULE ValkyrieBase){
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ValkyrieBase;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)((BYTE *)ValkyrieBase + DosHeader->e_lfanew);

    IMAGE_SECTION_HEADER *CurrentSection = (IMAGE_SECTION_HEADER *)((BYTE *)NtHeader + sizeof(IMAGE_NT_HEADERS));
    
    for(DWORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++){
        BYTE *SectionVASpace = (BYTE *)ValkyrieBase + CurrentSection->VirtualAddress;
        BYTE *SectionRawData = (BYTE *)ValkyrieBase + CurrentSection->PointerToRawData;
        DWORD RawDataSize    = CurrentSection->SizeOfRawData;

        if(strcmp((CHAR *)CurrentSection->Name, ".rdata") == 0){
            for(DWORD j = 0; j < RawDataSize; j++) {
                IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)(SectionRawData + j);
                if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                    IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)((BYTE *)DosHeader + DosHeader->e_lfanew);
                    if (NtHeader->Signature == IMAGE_NT_SIGNATURE) {
                        return (LPVOID)DosHeader;
                    }
                }
            }
        }
        CurrentSection++;
    }
    return NULL;
}

// Returns the byte size of the embedded module at EmbeddedModule
SIZE_T GetEmbeddedModuleSize(LPVOID EmbeddedModule, CHAR *EofPattern){
    for(SIZE_T i = 0; i < EMBEDDED_SIZE; i++){
        if(strcmp((BYTE *)EmbeddedModule + i, EofPattern) == 0){
            return i;
        }
    }
    return (SIZE_T)0;
}

// Translates offsets from executables on disk to valid offsets after loading into memory
DWORD OffsetResolver(HMODULE ModuleBase, DWORD RVA){
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ModuleBase;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)ModuleBase);

    IMAGE_SECTION_HEADER *SectionHeader = (IMAGE_SECTION_HEADER *)(NtHeader->FileHeader.SizeOfOptionalHeader + (BYTE *)&NtHeader->OptionalHeader);
    if(RVA < SectionHeader->PointerToRawData){
        return RVA;
    } else {
        DWORD SectionsQuantity = NtHeader->FileHeader.NumberOfSections;
        DWORD Counter = 0;
        while(SectionsQuantity){
            if(RVA >= SectionHeader[Counter].VirtualAddress && RVA <= SectionHeader[Counter+1].VirtualAddress){
                return (RVA - SectionHeader[Counter].VirtualAddress + SectionHeader[Counter].PointerToRawData);
            }
            Counter++;
            SectionsQuantity--;
        }
        return 0;
    }
}

// Parse the Export Address Table of an executable on disk to find the address of TargetFunction, translate the offset to a valid offset after loading into memory
DWORD LocateFunctionOffsetFromFile(LPVOID ModuleBase, CHAR *TargetFunction){
    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)ModuleBase;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)ModuleBase);

    if(DosHeader->e_magic != IMAGE_DOS_SIGNATURE || NtHeader->Signature != IMAGE_NT_SIGNATURE){
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(OffsetResolver(ModuleBase, NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) + (BYTE *)ModuleBase);

    DWORD *FunctionNameRVAs = (DWORD *)(OffsetResolver(ModuleBase, ExportDirectory->AddressOfNames)     + (BYTE *)ModuleBase);
    DWORD *FunctionRVAs     = (DWORD *)(OffsetResolver(ModuleBase, ExportDirectory->AddressOfFunctions) + (BYTE *)ModuleBase);

    for(DWORD i = 0; i < ExportDirectory->NumberOfNames; i++){
        CHAR *FunctionName = (CHAR *)(OffsetResolver(ModuleBase, FunctionNameRVAs[i]) + (BYTE *)ModuleBase);
        if(!strcmp(FunctionName, TargetFunction)){
            return OffsetResolver(ModuleBase, FunctionRVAs[i]);
        }
    }
    return 0;
}