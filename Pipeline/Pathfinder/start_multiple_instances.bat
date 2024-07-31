@echo off
setlocal

REM Check if the number of instances is provided as an argument
if "%~1"=="" (
    echo Usage: %~nx0 [number_of_instances] [python_script]
    exit /b 1
)

REM Check if the Python script path is provided as an argument
if "%~2"=="" (
    echo Usage: %~nx0 [number_of_instances] [python_script]
    exit /b 1
)

set "NUM_INSTANCES=%~1"
set "PYTHON_SCRIPT=%~2"
set "OPTIMIZATION_LEVEL=x"

REM Extract the directory of the Python script
for %%F in ("%PYTHON_SCRIPT%") do set "SCRIPT_DIR=%%~dpF"
set "SCRIPT_NAME=%~nx2"

REM Start the instances, for each also echo the start command
for /L %%i in (0,1,%NUM_INSTANCES%) do (
    echo Start instance %%i
    start "" powershell -Command "cd '%SCRIPT_DIR%'; $env:PYTHONOPTIMIZE = '%OPTIMIZATION_LEVEL%'; python3 .\%SCRIPT_NAME% %%i"
)

endlocal
