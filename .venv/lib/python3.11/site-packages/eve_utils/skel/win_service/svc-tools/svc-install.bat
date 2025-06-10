@echo off
setlocal

rem Check if running as elevated
net session >nul 2>&1
if %errorLevel% == 0 (
    goto iselevated
) else (
    echo Must run as administrator.
    goto end
)



:iselevated

set svcName={$project_name}
set svcPath=.\%svcName%.exe
if not exist %svcPath% goto error

set svcDescription=Service description goes here.

sc create "%svcName%" binPath= "%svcPath%" start= auto
sc description "%svcName%" "%svcDescription%"
sc start "%svcName%"
sc query "%svcName%"

goto end

:error
echo Cannot find %svcPath%


:end
endlocal