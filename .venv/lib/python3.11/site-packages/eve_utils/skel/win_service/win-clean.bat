@echo off
rd __pycache__ /s/q
rd build /s/q
rd dist /s/q
del {$project_name}.spec

