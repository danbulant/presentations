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
        language='bash'
        code={`
        $ ./hello
        `}
        fontSize={90}
    />);
    yield* slideTransition(Direction.Bottom);

    yield* beginSlide("program");

    yield* code().edit(.3)`
    $ ./hello
    ${insert(`
    Enter your name:
    `)}`;

    yield* beginSlide("enter name");

    yield* code().edit(.3)`
    $ ./hello
    Enter your name:${insert(` test`)}
    `;

    yield* beginSlide("entered name");

    yield*
    all(
        code().edit(.3, false)`
    $ ./hello
    Enter your name: test
    ${insert(`Welcome test
Enter your name:
    `)}`,
        code().selection(lines(2), .3)
    );

    yield* beginSlide("welcome");

    yield* code().selection(lines(3), .3);

    yield* beginSlide("repeat");
});
