@echo off
setlocal

net session >nul 2>&1
if %errorLevel% == 0 (
    goto iselevated
) else (
    echo Must run as administrator.
    goto end
)


:iselevated
set svcName={$project_name}

sc stop "%svcName%"
sc delete "%svcName%"




:end
endlocal

