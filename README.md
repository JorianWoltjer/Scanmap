# Scanmap

```
usage: main.py [-h] [-a] [-p PORTS] [-o OUTPUT] [-n] [-t TIMEOUT] [-T THREADS] [--os] [--json] network

positional arguments:
  network               'auto' for automatic detection, subnet, or single host (ex. 192.168.1.0/24 or 192.168.1.42)

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             enable all options, try to find everything
  -p PORTS, --ports PORTS
                        ports to scan for all found hosts. 'top', 'all', a range (ex. 1-1024), or a comma-separated list (ex. 22,80,443)
  -o OUTPUT, --output OUTPUT
                        save output to file in JSON format
  -n, --hostname        get hostname for all found hosts
  -t TIMEOUT, --timeout TIMEOUT
                        timeout for socket connections (in seconds)
  -T THREADS, --threads THREADS
                        number of threads to use for port scanning
  --os                  scan for operating system on all found hosts (requires ports)
  --json                output to stdout in JSON format
```

## Example

![sample_output](https://user-images.githubusercontent.com/26067369/155897182-2fead9a8-d1a6-4829-8b66-52a538da563a.png)
