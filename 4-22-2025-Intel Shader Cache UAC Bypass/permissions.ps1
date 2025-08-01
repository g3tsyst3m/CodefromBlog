$target = "C:\Users\robbi\AppData\LocalLow\Intel\ShaderCache"

# 2. Remove inheritance and wipe existing permissions
icacls $target /inheritance:r /T
icacls $target /remove:g "ANONYMOUS LOGON" "Guests" "Administrators" /T

# 3. Grant minimal permissions to the folder and subfolders
# (CI) - Container Inherit (subfolders)
# (OI) - Object Inherit (files)
# This only affects ACL propagation
icacls $target /grant:r "Authenticated Users:(OI)(CI)(RX,D)" /T

# 4. Explicitly overwrite ACLs on existing files with only (RX,D)
Get-ChildItem $target -Recurse -File | ForEach-Object {
    icacls $_.FullName /inheritance:r
    icacls $_.FullName /grant:r "Authenticated Users:(RX,D)"
}