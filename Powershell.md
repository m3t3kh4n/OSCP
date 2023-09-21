# PowerShell
```
powershell -ep bypass
```
## Execution Policy
- Get current Execution Policy
```
Get-ExecutionPolicy -Scope CurrentUser
```

- Set Execution Policy
```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```



## Base64 using PowerShell
```
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("<command>"))
```
- Also, `pwsh` can be used in Linux environment.

## Download
```
Invoke-WebRequest -URI $URL -OutFile $Path
```
```
(New-Object System.Net.WebClient).DownloadFile($URL, $Path)
```
```
Start-BitsTransfer -Source $URL -Destination $Path
```
