# Port Forwarding, Redirection & Tunnelling

## Classic Port Forwarding (Run command in Attacker, to forward the port available on Victim)
- `-L`

## Reverse Port Forwarding (Run command in Victim, to forward the port available on Victim to Attacker)
- `-R` [For this check ERP PG-Practice walkthrough]

# Examples
```
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```
- `-N`: avoid opening shell
