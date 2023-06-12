@echo off

REM Accepted arguments = "scan", "unhook", "aggressive", "verbose"

set "ARGUMENTS=%*"
setlocal enabledelayedexpansion
set "COMPILER_ARGUMENTS="
for %%A in (%ARGUMENTS%) do (
	set "COMPILER_ARGUMENTS=!COMPILER_ARGUMENTS! /D %%A"
)
cl.exe /nologo /wd 4024 /wd 4047 /LD /D DLL_BUILD %COMPILER_ARGUMENTS% src\Valkyrie.c user32.lib
del Valkyrie.obj