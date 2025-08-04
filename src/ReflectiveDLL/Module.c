#include "..\Shared\Valkyrie.h"

// Client-side (Module) IPC, receives arguments from Valkyrie.exe, transmits hook data from current process
VOID ReceiveArguments(HANDLE ValkyriePipeHandle, VALKYRIE_ARGUMENTS *Arguments){
    DWORD  TotalBytesAvailable = 0;
    DWORD  BytesRead           = 0;
    CHAR   Buffer[4096]        = { 0 };

    if(WaitForMessage(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_SYN)){
        WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_ACK);
    } else {
        ExitThread(EXIT_FAILURE);
    }

    while(TRUE){
        PeekNamedPipe(ValkyriePipeHandle, NULL, 0, NULL, &TotalBytesAvailable, NULL);
        if(TotalBytesAvailable){
            ReadFile(ValkyriePipeHandle, Buffer, sizeof(Buffer), &BytesRead, NULL);
            if(strcmp(Buffer, VALKYRIE_PIPE_ARGUMENT_UNHOOK) == 0){
                Arguments->Unhook = TRUE;
                WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_NEXT);
            }
            if(strcmp(Buffer, VALKYRIE_PIPE_ARGUMENT_ALLJMP) == 0){
                Arguments->ListAllJumps = TRUE;
                WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_NEXT);
            }
            if(strcmp(Buffer, VALKYRIE_PIPE_ARGUMENT_FINISH) == 0){
                return;
            }
            ZeroMemory(Buffer, sizeof(Buffer));
        }
    }
}

INT ModuleMain(){
    VALKYRIE_ARGUMENTS Arguments = { 0 };

    HANDLE  ValkyriePipeHandle = INVALID_HANDLE_VALUE;
    HMODULE ProcessBase        = NULL;

    LOADED_MODULE_LIST *LoadedModuleList = NULL;

    JUMP_CHAIN **JumpChain   = NULL;
    DWORD dwJumpChainNumber  = 0;
    CHAR JumpChainNumber[5]  = { 0 };

    ProcessBase = CustomGetModuleHandleHash(0);
    if(!ProcessBase){
        ExitThread(EXIT_FAILURE);
    }

    for(DWORD i = 0; i < VALKYRIE_PIPE_TIMEOUT; i++){
        ValkyriePipeHandle = CreateFileA(VALKYRIE_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if(ValkyriePipeHandle != INVALID_HANDLE_VALUE){
            WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_IDENTIFY_MODULE);
            break;
        } else {
            if(ValkyriePipeHandle == INVALID_HANDLE_VALUE && (i + 1) == VALKYRIE_PIPE_TIMEOUT){
                return FALSE;
            }
        }
    }

    ReceiveArguments(ValkyriePipeHandle, &Arguments);
    
    JumpChain = ScanImportedFunctions(ProcessBase, Arguments.Unhook, Arguments.ListAllJumps, &dwJumpChainNumber);

    if(WaitForMessage(ValkyriePipeHandle, VALKYRIE_PIPE_DATA_SYN)){
        WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_DATA_ACK);
    } else {
        ExitThread(EXIT_FAILURE);
    }

    snprintf(JumpChainNumber, sizeof(JumpChainNumber), "%d", dwJumpChainNumber);
    WriteToPipe(ValkyriePipeHandle, JumpChainNumber);
    WaitForPipeRead(ValkyriePipeHandle, JumpChainNumber);

    for(DWORD i = 0; i < dwJumpChainNumber; i++){
        //printf("[%s] Transmitting %s\n", MESSAGE_DEBUG, SerializeJumps(JumpChain[i]));
        WriteToPipe(ValkyriePipeHandle, SerializeJumps(JumpChain[i]));
        WaitForPipeRead(ValkyriePipeHandle, SerializeJumps(JumpChain[i]));
    }

    WriteToPipe(ValkyriePipeHandle, VAYLKRIE_PIPE_DATA_FINISH);
    WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_TERMINATE);

    MessageBoxA(NULL, "Hello from Valkyrie Reflective Module!", "Valkyrie", MB_OK);
    
    ExitThread(EXIT_SUCCESS);
}