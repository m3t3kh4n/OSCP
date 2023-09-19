
# enum4linux
- `-u`: username to use (default: "")
- `-p`: password to use (default: "")
- `-k`: user that exist on the remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none)
- `-U`: get user list
- `-M`: get machine list
- `-S`: get share list
- `-a`: all
- `-r`: user enumeration via RID cycling

# smbclient
List SMB Shares:
```
smbclient -L //192.168.217.10/
```
```
smbclient -L \\\\192.168.217.10
```

List SMB Shares (NULL):
```
smbclient -L //192.168.217.10/ -U ''
```

Connect to SMB Share:
```
smbclient //192.168.217.10/name/
```

Connect to SMB Share (NULL):
```
smbclient //192.168.217.10/name/ -U ''
```

# rpcclient
```
rpcclient -U "" 10.10.10.169
```
```
enumdomusers
```
```
enumdomgroups
```

# SMB Recursive download
```
prompt off
recurse
mget *
```

# `smbmap`
```
Recursively listing all directories and subdirectories
smbmap -u null -p null -H <IP> -s <Share$> -R
```

