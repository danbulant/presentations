import {Circle, makeScene2D} from '@motion-canvas/2d';
import {Direction, beginSlide, createRef, slideTransition} from '@motion-canvas/core';
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
        fontSize={120}
    />);

    yield* beginSlide("Intro");
});
