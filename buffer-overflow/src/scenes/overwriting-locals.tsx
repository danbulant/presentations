import {Circle, Layout, Ray, Rect, Txt, makeScene2D} from '@motion-canvas/2d';
import { CodeBlock, remove, insert, edit } from '@motion-canvas/2d/lib/components/CodeBlock';
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
});