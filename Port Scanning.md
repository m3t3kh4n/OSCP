# Port Scanning

## nmap
Ping Sweep
```
nmap -sn <subnet>
```

All Port Scan
```
nmap -p- -T4 --min-rate=800 -vv <ip>
```
```
nmap -p- -T4 -sC -sV -A -vv <ip>
```
```
nmap -p- -T4 -sC -sV -A -vv -n -Pn <ip>
```
```
nmap -p- -T4 -sC -sV -A -vv -n -Pn --script vuln <ip>
```

Normal Scan

# nc
```
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```
