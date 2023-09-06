# rsync (Port 873)


## Enumeration


- Connection
```
#CONNECTION
nc -vn 127.0.0.1 873

@RSYNCD: 31.0        <--- You receive this banner with the version from the server
@RSYNCD: 31.0        <--- Then you send the same info

#list                <--- Then you ask the sever to list
raidroot             <--- The server starts enumerating
USBCopy        	
NAS_Public     	
_NAS_Recycle_TOSRAID	<--- Enumeration finished

@RSYNCD: EXIT         <--- Sever closes the connection
```

```
nmap -sV --script "rsync-list-modules" -p 873 192.168.181.126
```

- Copy from `rsync` to local
```
rsync -av rsync://192.168.181.126:873/fox ./fox
```

- Write (Upload) (Put) via rsync
```
rsync -av home_user/.ssh/ rsync://username@192.168.0.123/home_user/.ssh
```
