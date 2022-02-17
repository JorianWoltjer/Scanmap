import socket

TARGET = "192.168.3.33"

try:
    print(socket.gethostbyaddr(TARGET))
except socket.herror:
    print("hostname not found")
