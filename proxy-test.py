import socket
import struct

# 0x11 client too old (trigger update dialog)
# 0x21 wrong username/password
# 0x31 error + opens support URL
# 0x52 generic login error
# 0x65 insecure password + opens account page
# 0x66 error + opens security center
# 0x70 login parameter error

opcode = 0xee
# doesnt matter much, will show "cant connect to garena+ server" if not valid
error_code = 0x66

# body = [opcode][4-byte error code LE][message]
body = bytes([opcode]) + struct.pack('<I', error_code)
# full packet = [4-byte LE length][body]
packet = struct.pack('<I', len(body)) + body

print('will send:', packet.hex())

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
    if data:
        c.sendall(packet)
        print('sent error packet')
    c.close()