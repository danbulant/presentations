import {Circle, Layout, Node, Ray, Rect, Txt, makeScene2D, saturate} from '@motion-canvas/2d';
import {DEFAULT, Direction, PossibleVector2, SignalValue, Vector2, all, beginSlide, createRef, delay, modify, slideTransition} from '@motion-canvas/core';
import { CodeBlock, remove, insert, edit, lines, word } from '@motion-canvas/2d/lib/components/CodeBlock';

const BACKGROUND = '#282C34';
const DARKER = '#21252B';
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
        language='c'
        code={`
        printf("%s", text)
        `}
        fontSize={120}
    />);

    yield* slideTransition(Direction.Bottom);

    yield* beginSlide("Add assembly");

    yield* code().edit(.3)`
    printf("%s", text)
    ${insert(`
    move rdi, text
    mov rax, "%s"
    call printf
    `)}`;

    yield* beginSlide("Add params");

    yield* all(
        code().edit(.3, false)`
    printf("%s", text${insert(", 1..6")})
    ${insert(`push    6
mov r9d, 5
mov r8d, 4
mov ecx, 3
mov edx, 2
mov esi, 1
`)}mov rdi, text
    mov rax, "%s
    call printf
    `,
        code().selection(lines(1, 10), .3)
    );

    yield* beginSlide("Add stack");

    const stackTitle = createRef<Txt>();
    const rect = createRef<Rect>();
    const innerLayout = createRef<Layout>();
    const prevFrame = createRef<Rect>();
    const rip = createRef<Rect>();
    const rbp = createRef<Rect>();

    view.add(<>
        <Rect
            ref={rect}
            height={1800}
            width={1000}
            fill={DARKER}
            radius={20}
            opacity={0}
            shadowColor={BLACK + "00"}
            clip
        >
            <Layout
                layout
                ref={innerLayout}
                direction="column"
                justifyContent={"start"}
                alignItems={"start"}
                width={1000}
                height={1800}
            >
                <Rect
                    height={200}
                    width='100%'
                    fill={GREEN}
                    ref={prevFrame}
                    >
                    <Txt width='100%' padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={200} fill={BLACK} text="Previous frame" fontFamily={'monospace'} />
                </Rect>
                <Rect
                    height={200}
                    width='100%'
                    fill={RED}
                    ref={rip}
                    >
                    <Txt width='100%' padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={200} fill={BLACK} text="RIP" fontFamily={'monospace'} />
                    <Txt width='100%' padding={[0, 20, 0, 0]} textAlign={'right'} lineHeight={200} fill={BLACK} text="8" fontFamily={'monospace'} />
                </Rect>
                <Rect
                    height={200}
                    width='100%'
                    fill={BLUE}
                    ref={rbp}
                    >
                    <Txt width='100%' padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={200} fill={BLACK} text="RBP" fontFamily={'monospace'} />
                    <Txt width='100%' padding={[0, 20, 0, 0]} textAlign={'right'} lineHeight={200} fill={BLACK} text="8" fontFamily={'monospace'} />
                </Rect>
            </Layout>
        </Rect>
        <Txt
            ref={stackTitle}
            text="STACK"
            position={() => [rect().x() - rect().width()/2 + 144/2 + 20, -950]}
            opacity={rect().opacity}
            fontFamily="monospace"
            fill={GRAY}
        />
    </>);


    yield* all(
        rect().x(3840/4, .3),
        rect().opacity(1, .3),
        code().x(-3840/4, .3),
        rect().shadowBlur(20, .3),
        rect().shadowOffset(10, .3),
        delay(.2, all(
            rect().shadowColor(BLACK + "50", .3),
            prevFrame().opacity(0).opacity(1, .2),
            prevFrame().margin([200,0,0,0]).margin(0, .2),
            delay(.2, all(
                rip().opacity(0).opacity(1, .2),
                rip().margin([200,0,0,0]).margin(0, .2),
                delay(.2, all(
                    rbp().opacity(0).opacity(1, .2),
                    rbp().margin([200,0,0,0]).margin(0, .2),
                ))
            ))
        ))
    );

    yield* beginSlide("Add text");
});
