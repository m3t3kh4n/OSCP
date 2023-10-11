# PowerShell

## Windows-like PowerShell Base64 Format
In Kali:
```
cat filename.ps1 | iconv -t UTF-16LE | base64 -w 0
```


---

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
---
# Print Integrity level of a process
To display the integrity level of a process, we can use tools such as Process Explorer2 or third-party PowerShell modules such as NtObjectManager.3 Let's assume the latter is already installed on the system.

Once we import the module with Import-Module,4 we can use Get-NtTokenIntegrityLevel5 to display the integrity level of the current process by retrieving and reviewing the assigned access token.
```
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
```
