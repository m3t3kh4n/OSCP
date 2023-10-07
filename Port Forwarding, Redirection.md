# Port Forwarding, Redirection & Tunnelling

## SSH Local Port Forwarding
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/83283981-232d-46a8-bb62-8d8fc8f0b4c0)
```
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```
- `-L`: local port forwarding
- `-N`: prevent a shell from being opened
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/1b3db331-b981-444e-a2b4-d643a754fd64)

## SSH Dynamic Port Forwarding
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/b2b74dd7-335a-4e51-a72a-e1a4f073b3b6)
```
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```
- `-D`: dynamic port forwarding
- `-N`: prevent a shell from being opened
```
socks5 192.168.50.63 9999
```
```
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

## SSH Remote Port Forwarding
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/d7198038-b069-40d9-b38a-8ba9b69fa4dc)
```
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/b73c75c5-c724-469b-b0d9-a45629131028)

## SSH Remote Dynamic Port Forwarding
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/2105d04b-51c5-402e-946e-99aa7e84344a)
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/ab80fbb5-4dbc-48c6-81bd-6c3d54f51dd5)
```
ssh -N -R 9998 kali@192.168.118.4
```
```
socks5 127.0.0.1 9999
```

## Classic Port Forwarding (Run command in Attacker, to forward the port available on Victim)
- `-L`

## Reverse Port Forwarding (Run command in Victim, to forward the port available on Victim to Attacker)
- `-R` [For this check ERP PG-Practice walkthrough]

# Examples
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/9b98418c-66e3-4bfa-a220-0ecd3db02387)
```
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```
- `-N`: avoid opening shell
