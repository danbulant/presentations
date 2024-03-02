# Buffer overflow presentation

Presentation about buffer overflow including libc and canary, using pwntools.

## Plan

Show the binary

Start working on python script:

```py
from pwn import *

# ---

bin = ELF('../challenges/hello')
libc = ELF('/usr/lib/libc.so.6')

# ---

context.terminal = "kitty"
context.arch = "amd64"

# io = process('../challenges/hello')
io = gdb.debug('../challenges/hello')

# show GDB window

io.interactive()


```
