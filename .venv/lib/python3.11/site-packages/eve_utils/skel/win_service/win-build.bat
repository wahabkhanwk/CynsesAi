pyinstaller --onefile --icon=win_service.ico -n {$project_name} run.py 
xcopy svc-tools\* dist
