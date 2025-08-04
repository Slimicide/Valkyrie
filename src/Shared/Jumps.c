#include <Windows.h>
#include <stdio.h>
#include "Valkyrie.h"

// Serializes a JUMP_CHAIN struct, returns pointer to serialized string
CHAR *SerializeJumps(JUMP_CHAIN *JumpChain){
    // Example
    // JUMP_COUNT:01|HOOK_TYPE:00|JUMP_01_MODULE:KERNEL32.DLL|JUMP_01_FUNCTION_NAME:NULL|JUMP_01_ADDRESS:0000000000000000

    DWORD StringSize       = 0;
    DWORD Offset           = 0;
    CHAR *SerializedString = NULL;

    StringSize += strlen("JUMP_COUNT:00|");
    StringSize += strlen("HOOK_TYPE:00|");

    for(DWORD i = 0; i < JumpChain->JumpCount; i++){
        StringSize += strlen("JUMP_00_FUNCTION_NAME:|");
        StringSize += strlen(JumpChain->Jumps[i]->FunctionName);
        StringSize += strlen("JUMP_00_ADDRESS:0000000000000000|");
        StringSize += strlen("JUMP_00_MODULE:|");
        StringSize += strlen(JumpChain->Jumps[i]->ModuleName);
    }

    StringSize += 1;
    SerializedString = (CHAR *)malloc(StringSize);
    Offset = sprintf(SerializedString, "JUMP_COUNT:%02d|HOOK_TYPE:%02d", JumpChain->JumpCount, JumpChain->Jumps[0]->HookType);

    for(DWORD i = 0; i < JumpChain->JumpCount; i++){
        Offset += sprintf(SerializedString + Offset, "|JUMP_%02d_FUNCTION:%s|JUMP_%02d_ADDRESS:%016llX|JUMP_%02d_MODULE:%s", i+1, JumpChain->Jumps[i]->FunctionName, i+1, (ULONGLONG)JumpChain->Jumps[i]->Address, i+1, JumpChain->Jumps[i]->ModuleName);
    }

    Offset += sprintf(SerializedString + Offset, "\0");
    return SerializedString;
}

// Deserializes a serialized JUMP_CHAIN struct, returns pointer to the resulting JUMP_CHAIN struct
JUMP_CHAIN *DeserializeJumps(CHAR *SerializedJumpChain){
    CHAR *ParsedString = SerializedJumpChain;
    DWORD Iterator     = 0;

    JUMP_CHAIN *Result = (JUMP_CHAIN *)malloc(sizeof(JUMP_CHAIN));

    CHAR *DataStart   = NULL;
    CHAR *DataEnd     = NULL;
    DWORD JumpCount   = 0;
    DWORD CurrentJump = 0;
    
    SIZE_T StringLength = strlen(SerializedJumpChain);

    while(TRUE){
        ParsedString = strchr(ParsedString, ':') + 1;

        DataStart = ParsedString;
        DataEnd   = strchr(DataStart, '|');

        if(DataEnd){
            *DataEnd = '\0';
        }

        ParsedString = DataEnd + 1;

        if(Iterator == EnumJumpCount){
            JumpCount = atoi(DataStart);

            if(JumpCount){
                Result->JumpCount = JumpCount;
                Result->Jumps = (JUMP **)malloc(sizeof(JUMP *) * JumpCount);

                for(DWORD i = 0; i < JumpCount; i++){
                    Result->Jumps[i] = (JUMP *)malloc(sizeof(JUMP));
                }

            } else {
                return NULL;
            }
            Iterator++;

        } else if(Iterator == EnumHookType){
            Result->Jumps[0]->HookType = atoi(DataStart);
            Iterator++;

        } else if(Iterator == EnumFunctionName){
            Result->Jumps[CurrentJump]->FunctionName = (CHAR *)malloc(strlen(DataStart) + 1);
            strcpy(Result->Jumps[CurrentJump]->FunctionName, DataStart);
            Iterator++;

        } else if(Iterator == EnumAddress){
            Result->Jumps[CurrentJump]->ModuleName = (CHAR *)malloc(strlen(DataStart) + 1);
            Result->Jumps[CurrentJump]->Address = (VOID *)strtoull(DataStart, NULL, 16);
            Iterator++;

        } else if(Iterator == EnumModuleName){
            strcpy(Result->Jumps[CurrentJump]->ModuleName, DataStart);

            if((CurrentJump + 1) < JumpCount){
                Iterator = EnumFunctionName;
                CurrentJump++;
            } else {
                return Result;
            }
        }
    }
}

// Returns a pointer to a JUMP_CHAIN struct for a discovered IAT hook
JUMP_CHAIN *BuildIATJumpChain(VOID *HookedAddress, VOID *ActualAddress, CHAR *FunctionName){
    LDR_DATA_TABLE_ENTRY *Module = DetermineModule(ActualAddress);
    CHAR *ModuleName = (CHAR *)malloc(VALKYRIE_MAX_STRING_LENGTH);
    WideToANSI(((UNICODE_STRING *)(Module->Reserved4))->Buffer, ModuleName, VALKYRIE_MAX_STRING_LENGTH);

    JUMP_CHAIN *Result = (JUMP_CHAIN *)malloc(sizeof(JUMP_CHAIN));
    ZeroMemory(Result, sizeof(JUMP_CHAIN));

    Result->JumpCount = 2;
    Result->Jumps     = (JUMP **)malloc(sizeof(JUMP *) * Result->JumpCount);

    Result->Jumps[0] = (JUMP *)malloc(sizeof(JUMP));
    Result->Jumps[0]->HookType     = HookTypeIAT;
    Result->Jumps[0]->Address      = ActualAddress;
    Result->Jumps[0]->ModuleName   = ModuleName;
    Result->Jumps[0]->FunctionName = FunctionName;

    Module = DetermineModule(HookedAddress);
    
    Result->Jumps[1] = (JUMP *)malloc(sizeof(JUMP));
    Result->Jumps[1]->HookType     = HookTypeIAT;
    Result->Jumps[1]->Address      = HookedAddress;

    if(Module){
        Result->Jumps[1]->ModuleName = (CHAR *)malloc(VALKYRIE_MAX_STRING_LENGTH);
        WideToANSI(((UNICODE_STRING *)(Module->Reserved4))->Buffer, Result->Jumps[1]->ModuleName, VALKYRIE_MAX_STRING_LENGTH);

        if(GetFunctionName(Module->DllBase, HookedAddress)){
            Result->Jumps[1]->FunctionName = GetFunctionName(Module->DllBase, HookedAddress);
        } else {
            Result->Jumps[1]->FunctionName = CLASSIFIER_NULL;
        }

    } else if(ProbeForValidMemory(Result->Jumps[1]->Address)){
        Result->Jumps[1]->ModuleName = CLASSIFIER_MEM_PRIVATE;
        Result->Jumps[1]->FunctionName = CLASSIFIER_NULL;
    } else {
        Result->Jumps[1]->ModuleName = CLASSIFIER_MEM_INVALID;
        Result->Jumps[1]->FunctionName = CLASSIFIER_NULL;
    }

    return Result;
}

// Returns a pointer to a JUMP_CHAIN struct for discovered JMP instructions at a function base
JUMP_CHAIN *BuildInlineJumpChain(VOID *JumpAddress){
    LDR_DATA_TABLE_ENTRY *Module = DetermineModule(JumpAddress);

    CHAR *ModuleName = (CHAR *)malloc(VALKYRIE_MAX_STRING_LENGTH);
    WideToANSI(((UNICODE_STRING *)(Module->Reserved4))->Buffer, ModuleName, VALKYRIE_MAX_STRING_LENGTH);

    JUMP_CHAIN *Result = (JUMP_CHAIN *)malloc(sizeof(JUMP_CHAIN));
    ZeroMemory(Result, sizeof(JUMP_CHAIN));

    VOID *CurrentJump = JumpAddress;
    VOID *JumpDestination = NULL;

    Result->JumpCount = 1;
    
    if(CheckForJump((BYTE *)CurrentJump)){
        while(CheckForJump((BYTE*)CurrentJump)){
            JumpDestination = DetermineJump((BYTE *)CurrentJump);
            Result->JumpCount++;
            CurrentJump = JumpDestination;
        }
    }

    Result->Jumps = (JUMP **)malloc(sizeof(JUMP *) * Result->JumpCount);
    CurrentJump = JumpAddress;

    Result->Jumps[0] = (JUMP *)malloc(sizeof(JUMP));
    Result->Jumps[0]->HookType = HookTypeInline;
    Result->Jumps[0]->Address = JumpAddress;
    Result->Jumps[0]->ModuleName = ModuleName;
    Result->Jumps[0]->FunctionName = GetFunctionName(Module->DllBase, JumpAddress);

    // Starts at 1 because 0 is the jump source
    for(DWORD i = 1; i < Result->JumpCount; i++){
        JumpDestination = DetermineJump((BYTE *)CurrentJump);

        if(JumpDestination){
            Result->Jumps[i] = (JUMP *)malloc(sizeof(JUMP));
            Result->Jumps[i]->Address = JumpDestination;

            Module = DetermineModule(JumpDestination);

            if(Module){
                Result->Jumps[i]->ModuleName = (CHAR *)malloc(VALKYRIE_MAX_STRING_LENGTH);
                WideToANSI(((UNICODE_STRING *)(Module->Reserved4))->Buffer, Result->Jumps[i]->ModuleName, VALKYRIE_MAX_STRING_LENGTH);

                CHAR *FunctionName = GetFunctionName(Module->DllBase, JumpDestination);
                if(FunctionName){
                    Result->Jumps[i]->FunctionName = FunctionName;
                } else {
                    Result->Jumps[i]->FunctionName = CLASSIFIER_NULL;
                }

            } else if(ProbeForValidMemory(Result->Jumps[i]->Address)){
                Result->Jumps[i]->ModuleName = CLASSIFIER_MEM_PRIVATE;
                Result->Jumps[i]->FunctionName = CLASSIFIER_NULL;
            } else {
                Result->Jumps[i]->ModuleName = CLASSIFIER_MEM_INVALID;
                Result->Jumps[i]->FunctionName = CLASSIFIER_NULL;
            }
        }
        CurrentJump = JumpDestination;
    }

    return Result;
}

// Grow JumpChainArray with enough capacity for 25 more JUMP_CHAIN pointers
VOID ExpandJumpChainArray(JUMP_CHAIN ***JumpChainArray, DWORD *MaxJumpChain){
    JUMP_CHAIN **TmpArray = (JUMP_CHAIN **)malloc(sizeof(JUMP_CHAIN *) * (*MaxJumpChain + 25));
    memcpy(TmpArray, *JumpChainArray, (sizeof(JUMP_CHAIN *) * *MaxJumpChain));
    *MaxJumpChain += 25;

    free(*JumpChainArray);
    *JumpChainArray = TmpArray;
    TmpArray = NULL;
    return;
}

// Print out the contents of JumpChain
VOID RevealJumpChain(JUMP_CHAIN *JumpChain){
    CHAR IATHook[]    = "IAT";
    CHAR InlineHook[] = "INLINE";
    CHAR *HookType    = NULL;

    if(JumpChain->Jumps[0]->HookType == HookTypeIAT){
        HookType = IATHook;
    } else {
        HookType = InlineHook;
    }

    printf("[%s%s%s][%s%s%s] %p -> [%s%s%s] %p (%s -> %s)\n",
        ANSI_YELLOW,
        HookType,
        ANSI_WHITE,

        ANSI_YELLOW,
        JumpChain->Jumps[0]->ModuleName,
        ANSI_WHITE,

        JumpChain->Jumps[0]->Address,

        ANSI_YELLOW,
        JumpChain->Jumps[JumpChain->JumpCount - 1]->ModuleName,
        ANSI_WHITE,

        JumpChain->Jumps[JumpChain->JumpCount - 1]->Address,

        JumpChain->Jumps[0]->FunctionName,
        JumpChain->Jumps[JumpChain->JumpCount - 1]->FunctionName
    );
    return;
}

// Returns TRUE if *CheckAddress contains a known JMP instruction, FALSE if not
BOOL CheckForJump(BYTE *CheckAddress){
    if(!ProbeForValidMemory((VOID *)CheckAddress)){
        return FALSE;
    }
    
    if(*CheckAddress == REX_BYTE){
        CheckAddress++;
    }
    return (*CheckAddress == SHORT_JUMP || *CheckAddress == NEAR_JUMP || *CheckAddress == MODRM_JUMP || *CheckAddress == LOOPNE_JUMP);
}

// Follows the JMP instruction at JumpSource, returns resulting address or NULL if no JMP
VOID *DetermineJump(BYTE *JumpSource){
    BOOL IndirectJump = FALSE;
    VOID *JumpDestination = NULL;
    LONG Offset = 0;
    DWORD OffsetSize = 0;

    if(!ProbeForValidMemory((VOID *)JumpSource)){
        return NULL;
    }

    if(*JumpSource == REX_BYTE){
        JumpSource++;
    }

    switch(*JumpSource){
        // EB XX -> Jumps to a destination within a short range from the current instruction, XX representing a signed 8-bit offset.
        case SHORT_JUMP:
            OffsetSize = 1; // 0xeb *XX*
            break;

        case LOOPNE_JUMP:
            OffsetSize = 1; // 0xe0 *XX*
            break;

        // E9 XX XX XX XX -> Jumps to a destination within a larger range than a short jump, XX representing a signed 32-bit offset.
        case NEAR_JUMP:
            OffsetSize = 4; // 0xe9 *XX XX XX XX*
            break;

        // FF -> Far more complicated, luckily 0xFF25 shows up almost exclusively.
        // This is an indirect jump - it will point to an address that contains the final jump destination.
        // Consult AMD64 Arch Programmer's Manual: https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24594.pdf Chapter 1.4
        case MODRM_JUMP:
            IndirectJump = TRUE;
            
            unsigned char ModRM = *(JumpSource + 1);         // Accessing the ModR/M byte after 0xFF
            unsigned char Mod   = (ModRM >> 6) & 0b00000011; // Bit 7, 6
            unsigned char Reg   = (ModRM >> 3) & 0b00000111; // Bit 5, 4, 3
            unsigned char Rm    =  ModRM       & 0b00000111; // Bit 2, 1, 0
            if(Mod == 0b00000000 && Rm == 0b00000101){       // 0xFF25 is common if not exclusively present
                OffsetSize = 4; // 0xff *XX YY YY YY YY* (XX == ModRM byte, YY == signed 32-bit displacement)
            }
            break;
    }

    if(!OffsetSize){
        return NULL;
    }

    BYTE *TmpJumpSource = JumpSource;
    
    if(*JumpSource == MODRM_JUMP){
        TmpJumpSource = JumpSource + 2; // Skip 0xFF<MODRM> to access offset
    } else {
        TmpJumpSource = JumpSource + 1; // Skip 0xE0||0xE9||0xEB to access offset
    }

    switch(OffsetSize){
        case 1: // 8-bit offset
            Offset = *(CHAR *)TmpJumpSource;
            break;
        case 4: // 32-bit offset
            Offset = *(DWORD *)TmpJumpSource;
            break;
        case 8: // 64-bit offset
            Offset = *(LONG *)TmpJumpSource;
            break;
    }  

    if(*JumpSource == MODRM_JUMP){
        JumpDestination = JumpSource + Offset + OffsetSize + 2;
    } else {
        JumpDestination = JumpSource + Offset + OffsetSize + 1;
    }

    // Fetch the real jump location from the resolved address
    if(IndirectJump){
        JumpDestination = *(VOID **)JumpDestination;
    }

    return JumpDestination;
}

// Returns TRUE if JumpChain contains a jump that appears illegitimate
BOOL IsMaliciousJump(JUMP_CHAIN *JumpChain){
    LOADED_MODULE_LIST *LoadedModuleList = GetLoadedModules();

    for(DWORD i = 0; i < JumpChain->JumpCount; i++){

        // Check #1 - Check for function jumps into private / invalid memory / non-exported functions in other modules.
        if(strcmp(JumpChain->Jumps[i]->ModuleName, CLASSIFIER_MEM_PRIVATE) == 0 || strcmp(JumpChain->Jumps[i]->ModuleName, CLASSIFIER_MEM_INVALID) == 0 || strcmp(JumpChain->Jumps[i]->FunctionName, CLASSIFIER_NULL) == 0){ // Note: Some legitimate functions (msvcrt!memset) jump to non-exported functions
            if(!CheckFunctionHookException(JumpChain->Jumps[0]->FunctionName)){
                //printf("[%s] Jump marked malicious: %s!%s -> %s!%s\n", 
                //    MESSAGE_DEBUG, 
                //    JumpChain->Jumps[0]->ModuleName, JumpChain->Jumps[0]->FunctionName,
                //    JumpChain->Jumps[i]->ModuleName, JumpChain->Jumps[i]->FunctionName
                //);
                return TRUE;
            }
        }

        // TODO Check #2 - A function exported by a signed module jumping to an unsigned module or module signed by another signer is likely a hook.

        // GetLoadedModule with JumpChain-Jump[i]->ModuleName to access module path on disk.
        // Convert to WCHAR.
        // WinVerifyTrust to grab signing certificates.
        // Compare certificates of module[i] and module[i+1].
    }

    return FALSE;
}