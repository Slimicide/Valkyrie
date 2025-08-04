#include <Windows.h>
#include "Valkyrie.h"

// Server-side (Valkyrie.exe) IPC control, transmitting Valkyrie arguments to loaded reflective module in remote process, receiving data back
JUMP_CHAIN **ValkyriePipeControl(HANDLE ModuleThread, VALKYRIE_ARGUMENTS Arguments, DWORD *JumpChainsCollected){
    HANDLE ValkyriePipeHandle  = INVALID_HANDLE_VALUE;
    BOOL   ModuleComplete      = FALSE;
    DWORD  JumpChainNumber     = 0;
    DWORD  TotalBytesAvailable = 0;
    DWORD  BytesRead           = 0;
    CHAR   Buffer[4096]        = { 0 };

    DWORD dwCurrentJumpChain = 0;
    JUMP_CHAIN **Result    = NULL;

    while(TRUE){

        ValkyriePipeHandle = CreateNamedPipeA(VALKYRIE_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 1, 4096, 4096, 0, NULL);

        if(ValkyriePipeHandle == INVALID_HANDLE_VALUE){
            printf("[%s] Pipe failed to open 0x%X\n", MESSAGE_ERROR, GetLastError());
            return NULL;
        }

        printf("[%s] Waiting for pipe connection - ", MESSAGE_INFO);
        ConnectNamedPipe(ValkyriePipeHandle, NULL);

        while(TRUE){
            ZeroMemory(Buffer, sizeof(Buffer));
            PeekNamedPipe(ValkyriePipeHandle, NULL, 0, NULL, &TotalBytesAvailable, NULL);

            if(GetLastError() == ERROR_BROKEN_PIPE){
                FlushFileBuffers(ValkyriePipeHandle);
                DisconnectNamedPipe(ValkyriePipeHandle);
                CloseHandle(ValkyriePipeHandle);
                ZeroMemory(Buffer, sizeof(Buffer));
                break;
            }
    
            if(TotalBytesAvailable){
                ReadFile(ValkyriePipeHandle, Buffer, sizeof(Buffer), &BytesRead, NULL);

                if(strcmp(Buffer, VALKYRIE_PIPE_IDENTIFY_LOADER) == 0){
                    printf("%sLOADER CONNECTED.%s\n\n", ANSI_GREEN, ANSI_WHITE);

                } else if(strcmp(Buffer, VALKYRIE_PIPE_IDENTIFY_MODULE) == 0){
                    printf("%sMODULE CONNECTED.%s\n", ANSI_GREEN, ANSI_WHITE);
                    WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_SYN);

                    if(!WaitForMessage(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_ACK)){
                        if(TerminateThread(ModuleThread, EXIT_FAILURE)){
                            printf("[%s] Timed out waiting for module ACK for argument exchange - thread destroyed.\n", MESSAGE_ERROR);
                            return NULL;
                        } else {
                            printf("[%s] Timed out waiting for module ACK for argument exchange - failed to destroy thread.\n", MESSAGE_ERROR);
                            return NULL;
                        }
                        ExitProcess(EXIT_FAILURE);
                    } else {
                        if(Arguments.ListAllJumps){
                            WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_ALLJMP);
                            WaitForMessage(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_NEXT);
                        }

                        if(Arguments.Unhook){
                            WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_UNHOOK);
                            WaitForMessage(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_NEXT);
                        }

                        // List additional future arguments here

                        WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_FINISH);
                        WaitForPipeRead(ValkyriePipeHandle, VALKYRIE_PIPE_ARGUMENT_FINISH);

                        printf("[%s] Successfully exchanged arguments with remote module.\n", MESSAGE_INFO);
                    }

                    WriteToPipe(ValkyriePipeHandle, VALKYRIE_PIPE_DATA_SYN);

                    if(!WaitForMessage(ValkyriePipeHandle, VALKYRIE_PIPE_DATA_ACK)){
                        if(TerminateThread(ModuleThread, EXIT_FAILURE)){
                            printf("[%s] Timed out waiting for module ACK for data exchange - thread destroyed.\n", MESSAGE_ERROR);
                            return NULL;
                        } else {
                            printf("[%s] Timed out waiting for module ACK for data exchange - failed to destroy thread.\n", MESSAGE_ERROR);
                            return NULL;
                        }
                    } else {
                        printf("[%s] Ready to receive data from remote module.\n", MESSAGE_INFO);

                        ZeroMemory(Buffer, sizeof(Buffer));
                        ReadFile(ValkyriePipeHandle, Buffer, sizeof(Buffer), &BytesRead, NULL);
                        JumpChainNumber = (DWORD)atoi(Buffer);
                        *JumpChainsCollected = JumpChainNumber;

                        Result = (JUMP_CHAIN **)malloc(sizeof(JUMP_CHAIN *) * JumpChainNumber);

                        while(TRUE){
                            ZeroMemory(Buffer, sizeof(Buffer));
                            ReadFile(ValkyriePipeHandle, Buffer, sizeof(Buffer), &BytesRead, NULL);

                            if(strcmp(Buffer, VAYLKRIE_PIPE_DATA_FINISH) == 0){
                                printf("[%s] Data transmission complete.\n", MESSAGE_INFO);
                                break;
                            } else {
                                Result[dwCurrentJumpChain] = DeserializeJumps(Buffer);
                                dwCurrentJumpChain++;
                            }
                        }
                    }

                } else if(strcmp(Buffer, VALKYRIE_PIPE_TERMINATE) == 0){
                    ModuleComplete = TRUE;
                    break;
                    
                } else {
                    printf("[%s][%d BYTES] %s", MESSAGE_PIPE, BytesRead, Buffer);
                }
            }
        }

        if(ModuleComplete){
            printf("[%s] Successfully disconnected from module.\n\n", MESSAGE_INFO);
            return Result;
        }

    }
}

// Write Message to hPipe, return TRUE if successful write, FALSE if not
BOOL WriteToPipe(HANDLE hPipe, CHAR *Message){
    DWORD MessageLength = strlen(Message);
    DWORD BytesWritten  = 0;

    WriteFile(hPipe, Message, MessageLength, &BytesWritten, NULL);

    if(BytesWritten){
        return TRUE;
    } else {
        return FALSE;
    }
}

// Waits for PreviousMessage to disappear from hPipe buffer
VOID WaitForPipeRead(HANDLE hPipe, CHAR *PreviousMessage){
    DWORD Attempt             = 0;
    DWORD TotalBytesAvailable = 0;
    CHAR  Buffer[4096]        = { 0 };

    while(Attempt < VALKYRIE_PIPE_TIMEOUT){
        PeekNamedPipe(hPipe, (LPVOID)&Buffer, 0, NULL, &TotalBytesAvailable, NULL);
        if(!TotalBytesAvailable || (TotalBytesAvailable && (strcmp(Buffer, PreviousMessage) != 0))){
            return;
        }
    }
    return;
}

// Returns TRUE if Message appears in hPipe buffer, FALSE if it times out
BOOL WaitForMessage(HANDLE hPipe, CHAR *Message){
    DWORD Attempt             = 0;
    DWORD BytesRead           = 0;
    DWORD TotalBytesAvailable = 0;
    CHAR  Buffer[4096]        = { 0 };

    while(Attempt < VALKYRIE_PIPE_TIMEOUT){
        PeekNamedPipe(hPipe, NULL, 0, NULL, &TotalBytesAvailable, NULL);
        if(TotalBytesAvailable){
            ReadFile(hPipe, Buffer, sizeof(Buffer), &BytesRead, NULL);
            if(strcmp(Buffer, Message) == 0){
                return TRUE;
            }
        }
        Attempt++;
        Sleep(VALKYRIE_PIPE_TIMEOUT);
    }
    return FALSE;
}