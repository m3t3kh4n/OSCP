# PowerShell

## Base64 using PowerShell
```
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("<command>"))
```
- Also, `pwsh` can be used in Linux environment.
