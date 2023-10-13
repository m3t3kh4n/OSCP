
1. bas64 ticket.kirbi.64 > ticket.kirbi
2. ticketConverter ticket.kirbi ticket.ccache
3. export KRB5CCNAME=ticket.ccache
4. klist

> Kerberos very specific with time. If there is a difference like 5-10m in your nmap result. NTP sync your time.

# Create silver ticket
```
getST
```
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/7d3aa454-40be-4e75-947f-14b703ddbf4f)
![image](https://github.com/m3t3kh4n/OSCP/assets/112255413/ea491793-104e-4dbf-b49c-05798f9a4cd1)
