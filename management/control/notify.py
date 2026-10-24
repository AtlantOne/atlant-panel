"""Minimal systemd readiness notification; no dependency or daemon control."""
import os
import socket


def ready():
    address=os.environ.get('NOTIFY_SOCKET')
    if not address:return
    if len(address)>107 or not address.startswith(('/','@')) or '\0' in address:
        raise ValueError('Invalid systemd notification address')
    if address.startswith('@'):address='\0'+address[1:]
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as connection:
        connection.settimeout(2)
        connection.connect(address)
        connection.sendall(b'READY=1')
