# FTP

- `-A`: Force active mode FTP.
```
ftp -A anonymous@192.168.199.53
```

- Enabling binary encoding while transferring the executable files:
```
# After logging in
binary
```

- Recursive download
```
wget -r ftp://user:pass@ip/
```

# Default Credentials
- https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt
```
hydra -C <the file given above> <ip> ftp
```

# SSL Connection
```
ftp-ssl -z secure -z verify=0 -p <ip>
```
