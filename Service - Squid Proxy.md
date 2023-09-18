# Squid Proxy

# Add Proxy
```
nano /etc/proxychains4.conf
http <ip> <port>
```
```
proxychains -q nmap -Pn -sT -T4 --top-ports 1000 192.168.57.189
proxychains -q nmap -Pn -sT -T4 --top-ports 1000 localhost
```
