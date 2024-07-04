# Information Gathering

## Virtual Host (VHost Enumeration)

```
#ffuf (-fs: filter out all the responses of that size)
ffuf -u http://example.com/ -H "Host: FUZZ.example.com" -w wordlist.txt -fs 1234

# (-r: follow redirect)
ffuf -u http://example.com/ -H "Host: FUZZ.example.com" -w wordlist.txt -fs 1234 -r

# Sometimes, we have to specify the ip address not domain.
ffuf -u http://10.0.0.1/ -H "Host: FUZZ.example.com" -w wordlist.txt -fs 1234

# wfuzz
wfuzz -u http://example.com -H "Host: FUZZ.example.com" -w wordlist.txt --hl 138

# gobuster (Pattern file includes something like: {GOBUSTER}.inlanefreight.htb)
gobuster vhost -u http://10.129.118.153 -w namelist.txt -p pattern --exclude-length 301 -t 10
```
