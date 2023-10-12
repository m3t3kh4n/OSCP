
1. bas64 ticket.kirbi.64 > ticket.kirbi
2. ticketConverter ticket.kirbi ticket.ccache
3. export KRB5CCNAME=ticket.ccache
4. klist

> Kerberos very specific with time. If there is a difference like 5-10m in your nmap result. NTP sync your time.
