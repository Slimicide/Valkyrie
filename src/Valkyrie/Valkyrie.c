#include "..\Shared\Valkyrie.h"

CONST CHAR CreateRDataSpace[EMBEDDED_SIZE] = { 0 };

VOID Usage(){
    printf("  -h, --help                        Display this usage message\n");
    printf("  -u, --unhook                      Attempt to unhook discovered function hooks\n");
    printf("  --list-all-jumps                  List all functions with jumps discovered at the base, malicious or not\n");
    printf("  --inject-pid <%s>                Inject Valkyrie into running process <%s>\n", VALKYRIE_ARGUMENT_PID, VALKYRIE_ARGUMENT_PID);
    printf("  --inject-new-process <%s>       Start a new instance of <%s> and inject Valkyrie\n", VALKYRIE_ARGUMENT_PATH, VALKYRIE_ARGUMENT_PATH);
    return;
}

INT main(INT argc, CHAR *argv[]){
    VALKYRIE_ARGUMENTS Arguments = { 0 };

    DWORD LocalJumpChainNumber    = 0;
    DWORD RemoteJumpChainNumber   = 0;
    JUMP_CHAIN **LocalJumpChains  = NULL;
    JUMP_CHAIN **RemoteJumpChains = NULL;

    DWORD  TargetPid    = 0;
    HANDLE TargetHandle = 0;

    LOADED_MODULE_LIST *LoadedModuleList   = NULL;
    HMODULE             ValkyrieBase       = NULL;
    LPVOID              EmbeddedModule     = NULL;
    SIZE_T              EmbeddedModuleSize = 0;

    LPVOID   SysAddr_NtAllocateVirtualMemory = NULL;
    HANDLE   ValkyriePipeHandle              = NULL;
    HMODULE  TargetAlloc                     = NULL;
    FARPROC  Loader                          = NULL;
    
    NTSTATUS Status                          = 0;
    SIZE_T   BytesWritten                    = 0;
    DWORD    LoaderOffset                    = 0;

    printf("\n%s", ANSI_YELLOW);
    printf("\t\t      \\\\                     //    \n");
    printf("\t\t       \\\\                   //     \n");
    printf("\t\t        \\\\%s V A L K Y R I E %s//  \n", ANSI_WHITE, ANSI_YELLOW);
    printf("\t\t         \\\\               //       \n");
    printf("\t\t          \\\\             //        \n");
    printf("\n%s", ANSI_WHITE);

    // Collect arguments
    if(argc < 2){
        printf("[%s] No arguments supplied.\n\n", MESSAGE_ERROR);
        Usage();
        ExitProcess(EXIT_FAILURE);
    }

    for(DWORD i = 1; i < argc; i++){

        // Help
        if(strcmp("-h", argv[i]) == 0 || strcmp("--help", argv[i]) == 0){
            Usage();
            ExitProcess(EXIT_SUCCESS);
        }

        // Unhook discovered hooks
        if(strcmp("-u", argv[i]) == 0 || strcmp("--unhook", argv[i]) == 0){
            Arguments.Unhook = TRUE;
            continue;
        }

        // List all jumps including legitimate ones
        if(strcmp("--list-all-jumps", argv[i]) == 0){
            Arguments.ListAllJumps = TRUE;
            continue;
        }

        // Deploy reflective module in active process of PID <PID>
        if(strcmp("--inject-pid", argv[i]) == 0){
            if(i+1 <= argc-1){
                Arguments.InjectPID = atoi(argv[i+1]);
                i++; // Skip the argument parameter
                continue;
            } else {
                printf("[%s] Missing PID for argument '--inject-pid'\n", MESSAGE_ERROR);
                Usage();
                ExitProcess(EXIT_FAILURE);
            }
        }

        // Deploy reflective module in new process at <PATH>
        if(strcmp("--inject-new-process", argv[i]) == 0){
            if(i+1 <= argc-1){
                Arguments.InjectProcess = argv[i+1];
                i++; // Skip the argument parameter
                continue;
            } else {
                printf("[%s] Missing executable path for argument '--inject-new-process'\n", MESSAGE_ERROR);
                Usage();
                ExitProcess(EXIT_FAILURE);
            }
        }

        printf("[%s] Unknown argument '%s'\n\n", MESSAGE_ERROR, argv[i]);
        Usage();
        ExitProcess(EXIT_FAILURE);
    }

    if(Arguments.InjectPID && Arguments.InjectProcess){
        printf("[%s] Cannot inject into both an existing process and new process, select one.\n", MESSAGE_ERROR);
        ExitProcess(EXIT_FAILURE);
    }

    ValkyrieBase = CustomGetModuleHandleHash(0);
    if(!ValkyrieBase){
        printf("[%s] Failed to get Valkyrie base.\n", MESSAGE_ERROR);
        ExitProcess(EXIT_FAILURE);
    }

    EmbeddedModule = FindEmbeddedModule(ValkyrieBase);
    if(!EmbeddedModule){
        printf("[%s] Failed to find embedded module, sections likely corrupted by module write.\n", MESSAGE_ERROR);
        ExitProcess(EXIT_FAILURE);
    }

    EmbeddedModuleSize = GetEmbeddedModuleSize(EmbeddedModule, "VALK-EOF");
    if(!EmbeddedModuleSize){
        printf("[%s] Failed to get embedded module size.\n", MESSAGE_ERROR);
        ExitProcess(EXIT_FAILURE);
    }

    // Scan Valkyrie.exe
    LocalJumpChains = ScanImportedFunctions(ValkyrieBase, Arguments.Unhook, Arguments.ListAllJumps, &LocalJumpChainNumber);
    
    if(LocalJumpChains){
        if(Arguments.ListAllJumps){
            printf("[%s] LOCAL PROCESS (Valkyrie.exe) ALL-JUMPS REPORT:\n", MESSAGE_INFO);
        } else {
            printf("[%s] LOCAL PROCESS (Valkyrie.exe) MALICIOUS-JUMPS REPORT:\n", MESSAGE_INFO);
        }
        if(!LocalJumpChainNumber){
                printf("[%s] %sNo jumps to report.%s\n", MESSAGE_INFO, ANSI_GREEN, ANSI_WHITE);
            }
        for(DWORD i = 0; i < LocalJumpChainNumber; i++){
            RevealJumpChain(LocalJumpChains[i]);
        }
        printf("\n");
    }

    if(Arguments.InjectProcess){
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));

        si.cb = sizeof(si);

        if(!CreateProcessA(NULL, Arguments.InjectProcess, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)){
            printf("[%s] Failed to create process %s\n", MESSAGE_ERROR, Arguments.InjectProcess);
            ExitProcess(EXIT_FAILURE);
        } else {
            TargetPid    = pi.dwProcessId;
            TargetHandle = pi.hProcess;
        }
    }

    if(Arguments.InjectPID){
        HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Arguments.InjectPID);
        if(ProcessHandle == INVALID_HANDLE_VALUE){
            printf("[%s] Failed to open process at PID %d\n", MESSAGE_ERROR, Arguments.InjectPID);
            ExitProcess(EXIT_FAILURE);
        } else {
            TargetPid    = Arguments.InjectPID;
            TargetHandle = ProcessHandle;
        }
    }

    if(TargetHandle && TargetPid){
        printf("[%s] Process PID:       %d\n", MESSAGE_INFO, TargetPid);
        printf("[%s] Process Handle:    0x%llX\n", MESSAGE_INFO, (ULONGLONG)TargetHandle);

        SysAddr_NtAllocateVirtualMemory = (LPVOID)((BYTE *)CustomGetProcAddress(CustomGetModuleHandleHash(HASH_DLL_NTDLL), HASH_FUNC_NTALLOCATEVIRTUALMEMORY) + 0x12);
        Status = Sys_NtAllocateVirtualMemory(TargetHandle, &(LPVOID)TargetAlloc, (ULONG_PTR)NULL, &EmbeddedModuleSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, SysAddr_NtAllocateVirtualMemory);
        if(TargetAlloc == NULL){
            printf("[%s] Failed to allocate remote memory buffer: %X\n", MESSAGE_ERROR, Status);
            ExitProcess(EXIT_FAILURE);
        }

        printf("[%s] Embedded Module:   %p\n", MESSAGE_INFO, EmbeddedModule);
        printf("[%s] Remote Allocation: %p\n", MESSAGE_INFO, TargetAlloc);

        if(!WriteProcessMemory(TargetHandle, TargetAlloc, EmbeddedModule, EmbeddedModuleSize, &BytesWritten)){
            printf("[%s] Failed to write local buffer to remote buffer: %X.\n", MESSAGE_ERROR, GetLastError());
            ExitProcess(EXIT_FAILURE);
        }

        LoaderOffset = LocateFunctionOffsetFromFile(EmbeddedModule, "TotallyNotAReflectiveLoader");

        Loader = (FARPROC)(LoaderOffset + (BYTE *)TargetAlloc);
        printf("[%s] Loader:            %p\n\n", MESSAGE_INFO, Loader);

        HANDLE ModuleThread = CreateRemoteThread(TargetHandle, NULL, 0, (LPTHREAD_START_ROUTINE)Loader, (HMODULE)TargetAlloc, 0, NULL);
        RemoteJumpChains = ValkyriePipeControl(ModuleThread, Arguments, &RemoteJumpChainNumber);

        if(RemoteJumpChains){
            if(Arguments.ListAllJumps){
                printf("[%s] REMOTE PROCESS (PID: %d) ALL-JUMPS REPORT:\n", MESSAGE_INFO, TargetPid);
            } else {
                printf("[%s] REMOTE PROCESS (PID: %d) MALICIOUS-JUMPS REPORT:\n", MESSAGE_INFO, TargetPid);
            }
            if(!RemoteJumpChainNumber){
                printf("[%s] %sNo jumps to report.%s\n", MESSAGE_INFO, ANSI_GREEN, ANSI_WHITE);
            }
            for(DWORD i = 0; i < RemoteJumpChainNumber; i++){
                RevealJumpChain(RemoteJumpChains[i]);
            }
            printf("\n");
        } else if(Arguments.InjectProcess){
            // If we failed to successfully retrieve data from a remote process we created, kill it
            TerminateProcess(TargetHandle, EXIT_FAILURE);
        }
    }

    ExitProcess(EXIT_SUCCESS);
}