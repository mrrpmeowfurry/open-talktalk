import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 9100))
s.listen(5)

print('listening on 9100...')

while True:
    c, a = s.accept()
    print('CONNECTION from', a)
    data = c.recv(4096)
    print('got', len(data), 'bytes:', data.hex())
    c.close()
