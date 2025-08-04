#include <Windows.h>
#include <stdio.h>
#include "..\Shared\Valkyrie.h"

// Hashing algorithm author: Dan Bernstein
// https://raw.githubusercontent.com/vxunderground/VX-API/main/VX-API/HashStringDjb2.cpp
ULONG HashDjb2(CHAR *FunctionName){
    ULONG hash = 0xfade; // Initial hash value
    INT c = 0;

    while (c = *FunctionName++){
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

INT main(INT argc, CHAR *argv[]){
    if(argc < 2){
        printf("Provide string argument to hash.\n");
        return EXIT_FAILURE;
    }
    printf("%X\n", HashDjb2(argv[1]));
    return EXIT_SUCCESS;
}