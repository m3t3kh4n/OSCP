# SMTP


```
sudo perl smtp-user-enum.pl -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 192.168.211.137 
```

# IMAP
```
#CONNECTION
nc 192.168.120.132 143

#LOGIN
tag login <username>@localhost <password>

#LIST EMAILS
tag LIST "" "*"

#READ EMAILS
tag SELECT <INBOX>

#FETCH the rest of the messages, and their headers, with the following command.
tag fetch 2:5 BODY[HEADER] BODY[1]
```
