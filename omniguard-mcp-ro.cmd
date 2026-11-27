@echo off



setlocal



if "%OMNIGUARD_DIR%"=="" set "OMNIGUARD_DIR=%~dp0"



if "%RELATE_EXE%"=="" set "RELATE_EXE=%LOCALAPPDATA%\Programs\relate\relate.exe"



if "%OMNIGUARD_DB%"=="" (



  if exist "%OMNIGUARD_DIR%omniguard.rl" (



    set "OMNIGUARD_DB=%OMNIGUARD_DIR%omniguard.rl"



  ) else (



    set "OMNIGUARD_DB=%OMNIGUARD_DIR%omniguard_demo.rl"



  )



)







"%RELATE_EXE%" serve --database "%OMNIGUARD_DB%" --read-only --mcp stdio 2>nul



if errorlevel 1 (



  "%RELATE_EXE%" serve --load "%OMNIGUARD_DB%" --mcp stdio



)



