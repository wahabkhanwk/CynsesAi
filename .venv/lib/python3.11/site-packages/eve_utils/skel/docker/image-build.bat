@echo off
setlocal
set repos={$project_name}

docker build -t %repos%:latest .

set LATESTIMAGE=
for /f %%i in ('docker images %repos%:latest --quiet') do set LATESTIMAGE=%%i

if not "x%1"=="x" docker tag %LATESTIMAGE% %repos%:%1 

set GITBRANCH=
for /f %%I in ('git.exe rev-parse --abbrev-ref HEAD 2^> NUL') do set GITBRANCH=%%I
@FOR /F "delims=" %%s IN ('powershell -command "((get-item env:'GITBRANCH').Value.ToLower()) -replace '/','-'"') DO @set GITBRANCH=%%s
if not "%GITBRANCH%"=="" docker tag %LATESTIMAGE% %repos%:%GITBRANCH%

: if "x%2"=="xN" goto end
: if "x%2"=="xn" goto end
: if "x%2"=="xY" goto push
: if "x%2"=="xy" goto push
: 
: choice /M "Push to ECR"
: if errorlevel 2 goto end
: 
: :push
: call image-push.bat %1

:end
endlocal