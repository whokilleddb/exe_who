@echo off

:: Preparing the environment
if not defined DevEnvDir (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)
rd /s /q .\out\
rd /s /q .\obj\
mkdir .\out\
mkdir .\obj\

:: Compiling C-sources
echo [i] Compiling C Sources
echo [i] Compiling modules
cl.exe /nologo /Ox /MT /W0 /GS- /c /I .\includes src\rewrite.c
if %errorlevel% neq 0 exit /b %errorlevel%
move rewrite.obj .\obj\


echo [!] Compiling Patcher
cl.exe /D_USRDLL /D_WINDLL /W0 /c /I .\includes src\patcher.c
if %errorlevel% neq 0 exit /b %errorlevel%
move patcher.obj .\obj\
link.exe /DLL .\obj\rewrite.obj .\obj\patcher.obj /OUT:out\patcher.dll
if %errorlevel% neq 0 exit /b %errorlevel%

echo [i] Checking Rust Sources
cargo check
if %errorlevel% neq 0 exit /b %errorlevel%

echo [i] Copying DLL 
copy .\out\patcher.dll .\target\debug\

echo [i] Test Run
cargo run -- --url https://google.com --pa