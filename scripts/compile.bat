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
if %errorlevel% neq 0 exit /b %errorlevel%

echo [!] Compiling Sandbox Detection Modules
cl.exe /D_USRDLL /D_WINDLL /W0 /c /I .\includes src\sandbox_detection.c
if %errorlevel% neq 0 exit /b %errorlevel%
move sandbox_detection.obj .\obj\

echo [!] Linking all modules together
link.exe /DLL .\obj\sandbox_detection.obj .\obj\rewrite.obj .\obj\patcher.obj /OUT:out\exe_who.dll
if %errorlevel% neq 0 exit /b %errorlevel%


echo [i] Checking Rust Sources
cargo check
if %errorlevel% neq 0 exit /b %errorlevel%

echo [i] Copying DLL 
copy .\out\exe_who.dll .\target\debug\

echo [i] Test Run
cargo run -- --url https://google.com --pa --ds --pe