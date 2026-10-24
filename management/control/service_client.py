"""Private Unix-socket client; never uses a shell, sudo or network proxy."""
import json
import socket
import struct


def request(path,action,body=None):
    if not hasattr(socket,'SO_PEERCRED'):raise OSError('Service helper requires Linux peer credentials')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(55)
        connection.connect(path)
        _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0:raise PermissionError('Service helper must be owned by root')
        payload=json.dumps({'action':action,'body':body},allow_nan=False).encode()+b'\n'
        if len(payload)>8192:raise ValueError('Service request too large')
        connection.sendall(payload)
        with connection.makefile('rb') as stream:raw=stream.readline(16385)
    if len(raw)>16384 or not raw.endswith(b'\n'):raise OSError('Invalid service response')
    response=json.loads(raw)
    if not isinstance(response,dict) or response.get('ok') is not True:raise OSError('Service operation failed')
    return response['result']
