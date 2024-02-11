import {Circle, Layout, Node, Ray, Rect, Txt, makeScene2D} from '@motion-canvas/2d';
import { CodeBlock, remove, insert, edit, lines } from '@motion-canvas/2d/lib/components/CodeBlock';
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
    const code = createRef<CodeBlock>();
    yield view.add(
        <CodeBlock
        ref={code}
        language='c'
        code={`
        #include <stdio.h>
        #include <stdlib.h>

        int main(void) {
            char local_30[32];
            int local_c = 0xdeadbeef;
            printf("Enter your name: ");
            gets(local_30);
            printf("Welcome %s!\\n", local_30);
            if(local_c != 0xdeadbeef) {
                printf("You win!\\n");
            }
            return 0;
        }
        `}
        fontSize={30}
    />);

    yield* beginSlide('C code');

    view.removeChildren();

    yield view.add(
        <CodeBlock
        ref={code}
        language='asm'
        code={`
    main:
        PUSH RBP
        MOV RBP, RSP
        SUB RSP, 0x30
        MOV DWORD PTR [RBP - 0xc], 0xdeadbeef
        LEA RAX,[s_Enter_your_name_]
        MOV RDI,RAX
        MOV EAX,0x0
        CALL libc.so.6::printf
        LEA RAX,[RBP - 0x30]
        MOV RDI,RAX
        MOV EAX,0x0
        CALL libc.so.6::gets
        LEA RAX,[RBP - 0x30]
        MOV RSI,RAX
        LEA RAX,[s_Welcome__s!]
        MOV RDI,RAX
        MOV EAX,0x0
        CALL libc.so.6::printf
        CMP DWORD PTR [RBP - 0xc],0xdeadbeef
        JZ not_win
        LEA RAX,[s_You_win!]
        MOV RDI,RAX
        CALL libc.so.6::puts
    not_win:
        MOV EAX,0x0
        LEAVE
        RET
        `}
        fontSize={30}
    />);

    yield* beginSlide('Assembly code');

    yield* code().edit(1.5, false)`
    main:
        PUSH RBP
        MOV RBP, RSP
        SUB RSP, 0x30
        MOV DWORD PTR [RBP - 0xc], 0xdeadbeef${
        remove(`
    LEA RAX,[s_Enter_your_name_]
    MOV RDI,RAX
    MOV EAX,0x0
    CALL libc.so.6::printf`)}
        LEA RAX,[RBP - 0x30]
        MOV RDI,RAX${
        remove(`
    MOV EAX,0x0`)}
        CALL libc.so.6::gets
        LEA RAX,[RBP - 0x30]
        MOV RSI,RAX
        LEA RAX,[s_Welcome__s!]
        MOV RDI,RAX${
        remove(`
    MOV EAX,0x0`)}
        CALL libc.so.6::printf
        CMP DWORD PTR [RBP - 0xc],0xdeadbeef
        JZ not_win
        LEA RAX,[s_You_win!]
        MOV RDI,RAX
        CALL libc.so.6::puts
    not_win:
        MOV EAX,0x0
        LEAVE
        RET`;

    yield* code().edit(1.5, false)`
    main:
        PUSH RBP
        MOV RBP, RSP
        SUB RSP, 0x30
        MOV DWORD PTR [RBP - 0xc], 0xdeadbeef
        ${edit(`LEA RAX,[RBP - 0x30]
    MOV RDI,RAX`, "LEA RDI,[RBP - 0x30]")}
        CALL libc.so.6::gets
        ${edit(`LEA RAX,[RBP - 0x30]
    MOV RSI,RAX`, "LEA RSI,[RBP - 0x30]")}
        ${edit(`LEA RAX,[s_Welcome__s!]
    MOV RDI,RAX`, "LEA RDI,[s_Welcome__s!]")}
        CALL libc.so.6::printf
        CMP DWORD PTR [RBP - 0xc],0xdeadbeef
        JZ not_win
        ${edit(`LEA RAX,[s_You_win!]
    MOV RDI,RAX`, "LEA RDI,[s_You_win!]")}
        CALL libc.so.6::puts
    not_win:
        MOV EAX,0x0
        LEAVE
        RET`;

    yield* code().edit(1.5, false)`
    main:
        PUSH RBP
        MOV RBP, RSP
        SUB RSP, 0x30${
        insert(`
    ; local_c = 0xdeadbeef`)}
        MOV DWORD PTR [RBP - 0xc], 0xdeadbeef
        LEA RDI,[RBP - 0x30]${
        insert(`
    ; gets(local_30)`)}
        CALL libc.so.6::gets
        LEA RSI,[RBP - 0x30]
        LEA RDI,[s_Welcome__s!]${
        insert(`
    ; printf(\"Welcome %s!\\n\", local_30)`)}
        CALL libc.so.6::printf${
        insert(`
    ; if(local_c != 0xdeadbeef)`)}
        CMP DWORD PTR [RBP - 0xc],0xdeadbeef
        JZ not_win
        LEA RDI,[s_You_win!]${
        insert(`
    ; puts(\"You win!\")`)}
        CALL libc.so.6::puts
    not_win:${
        insert(`
    ; return 0`)}
        MOV EAX,0x0
        LEAVE
        RET`;

    yield* beginSlide('Assembly code cleaned');

    yield* code().edit(1.5, false)`
    ${insert(`; int main(void)
; int               EAX:4           <RETURN>
; undefined4        Stack[-0xc]:4   local_c
; undefined1[44]    Stack[-0x38]... local_38
`)}main:
        PUSH RBP
        MOV RBP, RSP
        SUB RSP, 0x30
        ; local_c = 0xdeadbeef
        MOV DWORD PTR [RBP - 0xc], 0xdeadbeef
        LEA RDI,[RBP - 0x30]
        ; gets(local_30)
        CALL libc.so.6::gets
        LEA RSI,[RBP - 0x30]
        LEA RDI,[s_Welcome__s!]
        ; printf(\"Welcome %s!\\n\", local_30)
        CALL libc.so.6::printf
        ; if(local_c != 0xdeadbeef)
        CMP DWORD PTR [RBP - 0xc],0xdeadbeef
        JZ not_win
        LEA RDI,[s_You_win!]
        ; puts(\"You win!\")
        CALL libc.so.6::puts
    not_win:
        ; return 0
        MOV EAX,0x0
        LEAVE
        RET`;


    yield* beginSlide('Assembly code with header');

    yield* code().selection(lines(1), 1);
    yield* code().selection([...lines(1), ...lines(25)], 1);

    yield* beginSlide('return code highlighted');

    yield* code().selection(lines(2), 1);
    yield* code().selection([...lines(2), ...lines(8, 9), ...lines(17, 18)], 1);

    yield* beginSlide('local_c highlighted');

    yield* code().selection(lines(3), 1);
    yield* code().selection([...lines(3), ...lines(10, 13), ...lines(15)], 1);

    yield* beginSlide('local_30 highlighted');

    // memory visualization

    const rect = createRef<Rect>();
    const rbpRect = createRef<Rect>();
    const local_cRect = createRef<Rect>();
    const local_30Rect = createRef<Rect>();

    view.add(
    <Rect
        ref={rect}
        height={view.height() - 40}
        width={500}
        lineWidth={4}
        stroke={GRAY}
        opacity={0}
    >
        <Layout
            direction="column"
            width={500}
            height={view.height() - 40}
            layout
        >
            <Rect
                ref={rbpRect}
                height={150}
                width={500}
                fill={GREEN}
                stroke={GRAY}
                lineWidth={4}
                grow={2}
                alignItems={'center'}
            >
                <Txt width={500} textAlign={'center'} fill={BLACK} text="RBP" fontFamily={'monospace'} />
            </Rect>
            <Rect
                ref={local_cRect}
                height={100}
                width={500}
                fill={RED}
                stroke={GRAY}
                lineWidth={4}
                grow={1}
                alignItems={'center'}
            >
                <Txt width={500} textAlign={'center'} fill={BLACK} text="local_c" fontFamily={'monospace'} />
            </Rect>
            <Rect
                ref={local_30Rect}
                height={600}
                width={500}
                fill={CYAN}
                stroke={GRAY}
                lineWidth={4}
                grow={10}
                alignItems={'center'}
            >
                <Txt width={500} textAlign={'center'} fill={BLACK} text="local_30" fontFamily={'monospace'} />
            </Rect>
        </Layout>
    </Rect>
    );

    yield* all(
        code().selection(DEFAULT, .5),
        code().x(-code().width() / 2, 1),
        rect().opacity(1, .5),
        rect().x(rect().width() / 2 + 150, 1)
    );

    const writeArrow = createRef<Ray>();
    const metaInfo = createRef<Node>();
    view.add(<Node ref={metaInfo} opacity={0}>
        <Ray
            ref={writeArrow}
            fromX={rect().x() - rect().width() / 2 - 50}
            toX={rect().x() - rect().width() / 2 - 50}
            endArrow
            lineWidth={4}
            stroke={GRAY}
            fromY={local_30Rect().y() + local_30Rect().height() / 2}
            toY={local_30Rect().y() + local_30Rect().height() / 2}
            lineDash={[10, 10]}
        />
        <Txt topLeft={() => rbpRect().topRight().addX(rect().x() + 16)} text="RBP" fill={GRAY} fontFamily={'monospace'} fontSize={36} />
        <Txt left={() => rbpRect().right().addX(rect().x() + 16)} text="8" fill={GRAY} fontSize={36} />
        <Txt left={() => rbpRect().bottomRight().addX(rect().x() + 16)} text="RBP - 0x8" fill={GRAY} fontFamily={'monospace'} fontSize={36} />
        <Txt left={() => local_cRect().right().addX(rect().x() + 16)} text="4" fill={GRAY} fontFamily={'monospace'} fontSize={36} />
        <Txt left={() => local_cRect().bottomRight().addX(rect().x() + 16)} text="RBP - 0xC" fill={GRAY} fontFamily={'monospace'} fontSize={36} />
        <Txt left={() => local_30Rect().right().addX(rect().x() + 16)} text="44" fill={GRAY} fontFamily={'monospace'} fontSize={36} />
        <Txt bottomLeft={() => local_30Rect().bottomRight().addX(rect().x() + 16)} text={"RSP\n= RBP - 0x38"} fill={GRAY} fontFamily={'monospace'} fontSize={36} />
    </Node>)

    let writeArrowTo = writeArrow().to();
    writeArrowTo.y = local_30Rect().y() - local_30Rect().height() / 2;

    yield* all(
        metaInfo().opacity(1, 1),
        writeArrow().to(writeArrowTo, 1)
    );

    yield* beginSlide('Memory visualization');
});