#include "..\Shared\Valkyrie.h"

// Parses BaseAddress' Export Address Table to investigate the validity of CmpFunctionAddress as an address for the function identified by CmpFunctionIdentifier
// Returns the true function address if hooked, returns 0 if not hooked
ULONGLONG CheckForIATHook(HMODULE BaseAddress, ULONGLONG CmpFunctionIdentifier, ULONGLONG *CmpFunctionAddress){

    ULONGLONG CmpFunctionOrdinal =  (CmpFunctionIdentifier & IMAGE_ORDINAL_FLAG) ? CmpFunctionIdentifier : 0;
    CHAR     *CmpFunctionName    = !(CmpFunctionIdentifier & IMAGE_ORDINAL_FLAG) ? (CHAR *)CmpFunctionIdentifier : 0;

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);
    IMAGE_EXPORT_DIRECTORY *ExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (BYTE *)BaseAddress);

    DWORD *EAT             = (DWORD *)(ExportDirectory->AddressOfFunctions    + (BYTE *)BaseAddress);
    DWORD *FunctionName    = (DWORD *)(ExportDirectory->AddressOfNames        + (BYTE *)BaseAddress);
    WORD  *FunctionOrdinal = (WORD  *)(ExportDirectory->AddressOfNameOrdinals + (BYTE *)BaseAddress);

    if(CmpFunctionName){
        for(DWORD i = 0; i < ExportDirectory->NumberOfNames; i++){
            CHAR *CurrentFunctionName = (CHAR *)(FunctionName[i] + (BYTE *)BaseAddress);
            ULONGLONG CurrentFunctionAddress = (ULONGLONG)(EAT[FunctionOrdinal[i]] + (BYTE *)BaseAddress);
    
            if(strcmp(CurrentFunctionName, CmpFunctionName) == 0){
                if(CurrentFunctionAddress == *CmpFunctionAddress){
                    return 0;
                } else {
                    if(IsForwarder((CHAR *)CurrentFunctionAddress)){
                        CurrentFunctionAddress = (ULONGLONG)ProcessForwarder((CHAR *)CurrentFunctionAddress);
                        if(!CurrentFunctionAddress || CurrentFunctionAddress == *CmpFunctionAddress){
                            return 0;
                        }
                    } else {
                        return CurrentFunctionAddress;
                    }
                }
            }
        }
    } else if(CmpFunctionOrdinal){
        WORD Ordinal = (WORD)(CmpFunctionOrdinal & 0xFFFF);
        if (Ordinal >= ExportDirectory->Base && Ordinal < ExportDirectory->Base + ExportDirectory->NumberOfFunctions) {
            ULONGLONG OrdinalFunctionAddress = (ULONGLONG)(EAT[Ordinal - ExportDirectory->Base] + (BYTE *)BaseAddress);

            if (OrdinalFunctionAddress == *CmpFunctionAddress) {
                return 0;
            } else {
                if (IsForwarder((CHAR *)OrdinalFunctionAddress)) {
                    OrdinalFunctionAddress = (ULONGLONG)ProcessForwarder((CHAR *)OrdinalFunctionAddress);
                    if (OrdinalFunctionAddress == *CmpFunctionAddress) {
                        return 0;
                    }
                } else {
                    return OrdinalFunctionAddress;
                }
            }
        }
    }
    return FALSE;
}

// Parses BaseAddress' Import Address Table to check for both IAT hooks and inline hooks in imported functions
// Returns a list of discovered function hooks/jumps (depending on arguments) as JUMP_CHAIN pointers
JUMP_CHAIN **ScanImportedFunctions(HMODULE BaseAddress, BOOL Unhook, BOOL ListAllJumps, DWORD *JumpChainsCollected){
    DWORD MaxJumpChain     = 25;
    DWORD CurrentJumpChain = 0;

    JUMP_CHAIN **Result = (JUMP_CHAIN **)malloc(sizeof(JUMP_CHAIN *) * MaxJumpChain);

    ULONGLONG IATHook = 0;
    ULONGLONG CmpFunctionIdentifier = 0;

    IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)BaseAddress;
    IMAGE_NT_HEADERS *NtHeader  = (IMAGE_NT_HEADERS *)(DosHeader->e_lfanew + (BYTE *)BaseAddress);

    IMAGE_IMPORT_DESCRIPTOR *ImportDirectory  = (IMAGE_IMPORT_DESCRIPTOR *)(NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (BYTE *)BaseAddress);

    while(ImportDirectory->Name != 0){
        CHAR *ImportedModuleName = (CHAR *)(ImportDirectory->Name + (BYTE *)BaseAddress);
        LDR_DATA_TABLE_ENTRY *Module = GetLoadedModule(ImportedModuleName);

        IMAGE_THUNK_DATA *ILT = (IMAGE_THUNK_DATA *)(ImportDirectory->OriginalFirstThunk + (BYTE *)BaseAddress);
        IMAGE_THUNK_DATA *IAT = (IMAGE_THUNK_DATA *)(ImportDirectory->FirstThunk         + (BYTE *)BaseAddress);

        while(IAT->u1.Function != 0){
            IMAGE_IMPORT_BY_NAME *ImportByName = (IMAGE_IMPORT_BY_NAME *)(ILT->u1.AddressOfData + (BYTE *)BaseAddress);
            if(ILT->u1.Ordinal & IMAGE_ORDINAL_FLAG){
                CmpFunctionIdentifier = ILT->u1.Ordinal;
            } else {
                CmpFunctionIdentifier = (ULONGLONG)ImportByName->Name;
            }

            ULONGLONG IATHook = CheckForIATHook(Module->DllBase, CmpFunctionIdentifier, (ULONGLONG *)&IAT->u1.Function);

            if(IATHook){
                JUMP_CHAIN *JumpChain = BuildIATJumpChain((VOID *)IAT->u1.Function, (VOID *)IATHook, ImportByName->Name);

                if((CurrentJumpChain + 1) > MaxJumpChain){
                    ExpandJumpChainArray(&Result, &MaxJumpChain);
                }

                Result[CurrentJumpChain] = JumpChain;
                CurrentJumpChain++;

                if(Unhook){
                    UnhookIAT(&IAT->u1.Function, IATHook);
                }
            }
            
            if(CheckForJump((BYTE *)IAT->u1.Function)){
                JUMP_CHAIN *JumpChain = BuildInlineJumpChain((VOID *)IAT->u1.Function);
                
                if((CurrentJumpChain + 1) > MaxJumpChain){
                    ExpandJumpChainArray(&Result, &MaxJumpChain);
                }

                if(IsMaliciousJump(JumpChain)){
                    Result[CurrentJumpChain] = JumpChain;
                    CurrentJumpChain++;
                    if(Unhook){
                        if(!UnhookInline(JumpChain->Jumps[0]->Address, JumpChain->Jumps[0]->ModuleName)){
                            printf("[%s] Failed to unhook %s!%s\n", MESSAGE_ERROR, JumpChain->Jumps[0]->ModuleName, JumpChain->Jumps[0]->FunctionName);
                        }
                    }
                } else {
                    if(ListAllJumps){
                        Result[CurrentJumpChain] = JumpChain;
                        CurrentJumpChain++;
                    }
                }
            }
            IAT++;
            ILT++;
        }
        ImportDirectory++;
    }
    *JumpChainsCollected = CurrentJumpChain;
    
    return Result;
}