import {Circle, Layout, Line, Node, Ray, Rect, Txt, makeScene2D, saturate} from '@motion-canvas/2d';
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
    const paddingNotif = createRef<Txt>();
    const canary = createRef<Rect>();
    const loop = createRef<Rect>();
    const name = createRef<Rect>();
    const nameText1 = createRef<Txt>();
    const nameText2 = createRef<Txt>();

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
                <Rect
                    height={200}
                    width='100%'
                    ref={paddingNotif}
                    >
                    <Txt width='100%' padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={200} fill={WHITE} text="Padding" fontFamily={'monospace'} />
                    <Txt width='100%' padding={[0, 20, 0, 0]} textAlign={'right'} lineHeight={200} fill={GRAY} text="8" fontFamily={'monospace'} />
                </Rect>
                <Rect
                    height={200}
                    width='100%'
                    fill={YELLOW}
                    ref={canary}
                    >
                    <Txt width='100%' padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={200} fill={BLACK} text="Canary" fontFamily={'monospace'} />
                    <Txt width='100%' padding={[0, 20, 0, 0]} textAlign={'right'} lineHeight={200} fill={BLACK} text="8" fontFamily={'monospace'} />
                </Rect>
                <Rect
                    height={100}
                    width='100%'
                    fill={MAGENTA}
                    ref={loop}
                    >
                    <Txt width='100%' padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={100} fill={BLACK} text="Loop" fontFamily={'monospace'} />
                    <Txt width='100%' padding={[0, 20, 0, 0]} textAlign={'right'} lineHeight={100} fill={BLACK} text="4" fontFamily={'monospace'} />
                </Rect>
                <Rect
                    height={700}
                    width='100%'
                    fill={CYAN}
                    ref={name}
                    >
                    <Txt width='100%' height='100%' ref={nameText1} padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={700} fill={BLACK} text="Name" fontFamily={'monospace'} />
                    <Txt width='100%' height='100%' ref={nameText2} padding={[0, 20, 0, 0]} textAlign={'right'} lineHeight={700} fill={BLACK} text="32" fontFamily={'monospace'} />
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
    );

    yield* beginSlide("Add 6");

    let printfParam = createRef<Rect>();

    innerLayout().add(<>
        <Rect
            height={200}
            width='100%'
            fill={RED}
            ref={printfParam}
            >
            <Txt width='100%' height='100%' padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={200} fill={BLACK} text="6" fontFamily={'monospace'} />
            <Txt width='100%' height='100%' padding={[0, 20, 0, 0]} textAlign={'right'} lineHeight={200} fill={BLACK} text="8" fontFamily={'monospace'} />
        </Rect>
    </>);

    yield* all(
        name().height(500, .3),
        printfParam().height(0).height(200, .3),
        nameText1().lineHeight(500, .3),
        nameText2().lineHeight(500, .3),
    );

    yield* beginSlide("Read stack");

    let printfreadheight = 100;
    let line = createRef<Line>();
    view.add(<>
        <Line
            ref={line}
            points={[
                [50, printfreadheight],
                [-50, printfreadheight],
                [-50, -printfreadheight],
                [50, -printfreadheight]
            ]}
            stroke={GRAY}
            lineWidth={4}
            radius={20}
            position={[400, 800]}
            />
    </>);

    yield* all(code().edit(.3, true)`
    printf("${edit("%s", "%7$p")}", text, 1..6)
    push    6
    mov r9d, 5
    mov r8d, 4
    mov ecx, 3
    mov edx, 2
    mov esi, 1
    mov rdi, text
    mov rax, "%s
    call printf
    `,
        code().x(-3840/4+80, .3),
        line().position([300, 800]).position([400,800], .3),
        line().opacity(0).opacity(1, .3)
    );

    yield* beginSlide("Remove 6 again");

    yield* all(
        name().height(700, .3),
        printfParam().height(0, .3),
        nameText1().lineHeight(700, .3),
        nameText2().lineHeight(700, .3),
        code().selection(DEFAULT, .3),
        code().edit(.3, false)`
        printf("%7$p", text, 1..${edit("6","5")})
        ${remove(`push    6
`)}mov r9d, 5
        mov r8d, 4
        mov ecx, 3
        mov edx, 2
        mov esi, 1
        mov rdi, text
        mov rax, "%s
        call printf
        `
    );

    printfParam().remove();

    yield* beginSlide("Read canary");

    yield* all(
        line().y(0, .3),
        code().edit(.3, false)`
        printf("%${edit("7", "??")}$p", text, 1..5)
        mov r9d, 5
        mov r8d, 4
        mov ecx, 3
        mov edx, 2
        mov esi, 1
        mov rdi, text
        mov rax, "%s
        call printf
        `
    );

    yield* beginSlide("");
});
