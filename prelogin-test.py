import socket, struct, sys

# let us try different status ints. The gate maps a parsed status-input -> {0,5,9} via a table
# where input 2->5 and 4->9 are the "valid" ones. We don't know exactly which reply
# field is that input, so this version lets you set int1/int2 and the strings, and
# holds the socket open indefinitely so the client can proceed.

INT1 = int(sys.argv[1]) if len(sys.argv) > 1 else 2   # try 2, then 4, then 0
INT2 = int(sys.argv[2]) if len(sys.argv) > 2 else 0

def build_reply(opcode=0x0b, int1=INT1, int2=INT2, s1=b"0", s2=b"0"):
    body  = bytes([opcode])
    body += struct.pack('<I', int1)
    body += struct.pack('<I', int2)
    body += s1 + b"\x00"
    body += s2 + b"\x00"
    return struct.pack('<I', len(body)) + body

reply = build_reply()
print("config: int1=%d int2=%d" % (INT1, INT2))
print("will reply with:", reply.hex())

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 9100))
s.listen(5)
print('listening on 9100, holding connections OPEN...')

while True:
    c, a = s.accept()
    print('\nCONNECTION from', a)
    try:
        data = c.recv(4096)
        print('got', len(data), 'bytes:', data.hex())
        if data and len(data) >= 6 and data[4] in (0x0a, 0x0b):
            uname = data[10:].split(b'\x00')[0].decode(errors='replace')
            print('  username:', repr(uname))
            c.sendall(reply)
            print('  sent reply (int1=%d), holding open, watching for next packet...' % INT1)
            c.settimeout(120)  # very long - never hang up first
            try:
                while True:
                    more = c.recv(4096)
                    if not more:
                        print('  client closed')
                        break
                    print('  >>> CLIENT SENT:', len(more), 'bytes:', more.hex())
                    # if it sent something, try to decode opcode
                    if len(more) >= 5:
                        print('      opcode 0x%02x, len field %d' % (more[4], struct.unpack('<I', more[:4])[0]))
            except socket.timeout:
                print('  (120s, no more data)')
    except Exception as e:
        print('  error:', e)
    finally:
        c.close()