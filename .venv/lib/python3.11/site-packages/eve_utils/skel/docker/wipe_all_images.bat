@echo off
setlocal

echo About to delete all images containing the string "{$project_name}"
SET /P AREYOUSURE=Are you sure (Y/[N])?
IF /I "%AREYOUSURE%" NEQ "Y" GOTO END

for /F %%i in ('docker image ls --format "{{.Repository}}:{{.Tag}}" --filter "reference={$project_name}"') do docker image rm %%i -f

:end
endlocal
