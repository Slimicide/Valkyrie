@echo off

:: Make a "bin" folder if one doesn't already exist
if not exist "bin" mkdir bin

:: Use NASM to compile indirect syscall functions
nasm.exe -fwin64 -o Syscall.obj src\Shared\Syscall.asm

:: HashGenerator creates the Djb2 hashes in Valkyrie.h
::cl.exe /nologo src\Dev\HashGenerator.c /Fe:bin\HashGenerator.exe

:: Main executable
cl.exe /nologo ^
    src\Shared\Utilities.c src\Shared\Cryptography.c src\Shared\IPC.c ^
    src\Shared\Jumps.c src\Shared\ModuleResolution.c src\Shared\Scan.c ^
    src\Shared\Hooks.c src\Valkyrie\Valkyrie.c syscall.obj ^
    /Fe:bin\Valkyrie.exe

:: Reflective module - remove security features like stack canaries to avoid crashes
cl.exe /nologo /GS- /LD ^
    src\Shared\Utilities.c src\Shared\Cryptography.c src\Shared\IPC.c ^
    src\Shared\Jumps.c src\Shared\ModuleResolution.c src\Shared\Scan.c ^
    src\Shared\Hooks.c src\ReflectiveDLL\ReflectiveLoader.c src\ReflectiveDLL\Module.c ^
    src\Shared\Debug.c Syscall.obj user32.lib ^
    /Fe:bin\LdrValkyrie.dll

:: Delete leftover compilation products
del ^
    ReflectiveLoader.obj HashGenerator.obj bin\LdrValkyrie.exp bin\LdrValkyrie.lib ^
    Valkyrie.obj Syscall.obj Cryptography.obj IPC.obj Jumps.obj ModuleResolution.obj ^
    Utilities.obj Debug.obj Hooks.obj Module.obj Scan.obj

:: Embed the reflective module inside .rdata of Valkyrie.exe
py src\Dev\EmbedModule.py

:: Delete the module on disk after it has been embedded into Valkyrie.exe
del bin\LdrValkyrie.dll