@echo off
setlocal enabledelayedexpansion

set VHD_PATH=C:\Temp\DocumentUpdate.vhdx
set VHD_SIZE_MB=64
set EXE_TO_COPY=C:\Temp\DocumentRetrieval.exe
set SCRIPT_TO_COPY=C:\Temp\UMPDC.dll

echo [+] Creating 1GB VHDX...
(
echo create vdisk file="%VHD_PATH%" maximum=%VHD_SIZE_MB% type=expandable
echo select vdisk file="%VHD_PATH%"
echo attach vdisk
echo create partition primary
echo format fs=ntfs label="Documents2026" quick
echo assign letter=X
) | diskpart > nul 2>&1

REM Detect actual letter if X taken
for %%d in (X Y Z W V U T S R Q P O N M L K J I H G F E D C B A) do (
    if exist %%d:\ (
        echo [+] Drive %%d: available? No.
    ) else (
        echo [+] Assigning %%d:
        echo select disk !disknum!
        echo select partition 1
        echo assign letter=%%d
        ) | diskpart > nul 2>&1
        set DRIVE_LETTER=%%d
        goto :copy
    )
)

:copy

xcopy "%EXE_TO_COPY%" "%DRIVE_LETTER%:\"
echo [+] Copied to %DRIVE_LETTER%:\

xcopy "%SCRIPT_TO_COPY%" "%DRIVE_LETTER%:\" /h
echo [+] Copied to %DRIVE_LETTER%:\

echo select vdisk file="%VHD_PATH%"
echo detach vdisk
) | diskpart > nul 2>&1

echo [+] Done: %VHD_PATH% (test mount on target)
pause