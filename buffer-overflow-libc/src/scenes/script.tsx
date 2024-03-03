import {Circle, makeScene2D} from '@motion-canvas/2d';
import {Direction, all, beginSlide, createRef, slideTransition} from '@motion-canvas/core';
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
    io.sendline(b"%7$p")`)}`,
    code().selection(lines(12), .3));
});
