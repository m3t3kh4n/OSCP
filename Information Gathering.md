
# Subdomain Enumeration

```
ffuf -u "http://board.htb" -H "Host: FUZZ.board.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 15949
```
