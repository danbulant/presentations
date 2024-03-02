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

function fromTo(a: Node, b: Node, value: SignalValue<PossibleVector2>) {
    return modify(value, v =>
      a
        .worldToParent()
        .inverse()
        .multiply(b.worldToParent())
        .transformPoint(new Vector2(v)),
    );
  }

export default makeScene2D(function* (view) {
    const code = createRef<CodeBlock>();
    yield view.add(
        <CodeBlock
        ref={code}
        language='c'
        code={`
        undefined8 main(void)
        {
            long lVar1;
            bool bVar2;
            char *pcVar3;
            long in_FS_OFFSET;
            char name [32];
            int loop;
            
            lVar1 = *(long *)(in_FS_OFFSET + 0x28);
            bVar2 = true;
            setbuf(stdout,(char *)0x0);
            setbuf(stderr,(char *)0x0);
            while (bVar2) {
                printf("Enter your name: ");
                pcVar3 = gets(name);
                if ((int)pcVar3 == 0) {
                    puts("Bye bye");
                    bVar2 = false;
                }
                else {
                    printf("Welcome ");
                    printf(name);
                    putchar(10);
                }
            }
            if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                /* WARNING: Subroutine does not return */
                __stack_chk_fail();
            }
            return 0;
        }
        `}
        fontSize={50}
    />);

    yield* slideTransition(Direction.Top);
    yield* beginSlide("Cleanup");

    yield* code().edit(.4, false)`
    ${edit("undefined8", "long")} main(${remove("void")})
    {
        ${remove(`long lVar1;
        bool bVar2;
        char *pcVar3;
        long in_FS_OFFSET;
        `)}char name [32];
        int loop${insert(" = true")};

        ${insert("long ")}${edit("lVar1","stackchk")} = *(long *)(in_FS_OFFSET + 0x28);${remove(`
        bVar2 = true;`)}
        setbuf(stdout,(char *)0x0);
        setbuf(stderr,(char *)0x0);
        while (${edit("bVar2","loop")}) {
            printf("Enter your name: ");
            ${insert("int ")}pcVar3 = gets(name);
            if (${remove("(int)")}pcVar3 == 0) {
                puts("Bye bye");
                ${edit("bVar2","loop")} = false;
            }
            else {
                printf("Welcome ");
                printf(name);
                putchar(${edit("10", "'\\n'")});
            }
        }
        if (${edit("lVar1","stackchk")} != *(long *)(in_FS_OFFSET + 0x28)) {${remove(`
            /* WARNING: Subroutine does not return */`)}
            __stack_chk_fail();
        }
        return 0;
    }
    `;
    yield* code().edit(.4, false)`
    long main()
    {
        ${insert(`
        // undefined8        Stack[-0x10]:8 stackchk
        // int               Stack[-0x18]:4 loop
        // char[32]          Stack[-0x38]   name

        `)}char name [32];
        int loop = true;

        long stackchk = *(long *)(in_FS_OFFSET + 0x28);
        setbuf(stdout,(char *)0x0);
        setbuf(stderr,(char *)0x0);
        while (loop) {
            printf("Enter your name: ");
            int pcVar3 = gets(name);
            if (pcVar3 == 0) {
                puts("Bye bye");
                loop = false;
            }
            else {
                printf("Welcome ");
                printf(name);
                putchar('\\n');
            }
        }
        if (stackchk != *(long *)(in_FS_OFFSET + 0x28)) {
            __stack_chk_fail();
        }
        return 0;
    }
    `;
    yield* code().edit(.4, false)`
    long main()
    {
        // ${edit("undefined8", "long      ")}        Stack[-0x10]:8 stackchk
        // int               Stack[-0x18]:4 loop
        // char[32]          Stack[-0x38]   name

        char name [32];
        int loop = true;

        long stackchk = *(long *)(in_FS_OFFSET + 0x28);
        setbuf(stdout,(char *)0x0);
        setbuf(stderr,(char *)0x0);
        while (loop) {
            printf("Enter your name: ");
            int pcVar3 = gets(name);
            if (pcVar3 == 0) {
                puts("Bye bye");
                loop = false;
            }
            else {
                printf("Welcome ");
                printf(name);
                putchar('\\n');
            }
        }
        if (stackchk != *(long *)(in_FS_OFFSET + 0x28)) {
            __stack_chk_fail();
        }
        return 0;
    }
    `;

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

    yield* beginSlide("Add canary to stack");

    const paddingNotif = createRef<Txt>();
    const canary = createRef<Rect>();

    innerLayout().add(<>
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
    </>);

    yield* all(
        paddingNotif().opacity(0).opacity(1, .3),
        paddingNotif().margin([200,0,0,0]).margin(0, .3),
        delay(.2, all(
            canary().opacity(0).opacity(1, .3),
            canary().margin([200,0,0,0]).margin(0, .3),
        ))
    );

    yield* beginSlide("Add locals to stack");

    const loop = createRef<Rect>();
    const name = createRef<Rect>();

    innerLayout().add(<>
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
            <Txt width='100%' height='100%' padding={[0, 0, 0, 20]} textAlign={'left'} lineHeight={700} fill={BLACK} text="Name" fontFamily={'monospace'} />
            <Txt width='100%' height='100%' padding={[0, 20, 0, 0]} textAlign={'right'} lineHeight={700} fill={BLACK} text="32" fontFamily={'monospace'} />
        </Rect>
    </>);

    yield* all(
        loop().opacity(0).opacity(1, .3),
        loop().margin([200,0,0,0]).margin(0, .3),
        delay(.2, all(
            name().opacity(0).opacity(1, .3),
            name().margin([200,0,0,0]).margin(0, .3),
        ))
    );

    yield* beginSlide("the bug");

    yield* all(
        code().selection([
            ...word(14, 25, 10)
        ], .3),
        prevFrame().filters.saturate(.3, .3),
        rip().filters.saturate(.3, .3),
        rbp().filters.saturate(.3, .3),
        loop().filters.saturate(.3, .3),
        canary().filters.saturate(.3, .3),
        paddingNotif().opacity(.5, .3),
    );

    yield* beginSlide("printf");

    yield* code().selection([
        ...word(21, 15, 13)
    ], .3);

    yield* beginSlide("stackchk");

    yield* all(
        code().selection([
            ...lines(9),
            ...lines(25, 27)
        ], .3),
        canary().filters.saturate(1, .3),
        name().filters.saturate(.3, .3)
    );

    yield* beginSlide("writing");

    const ray = createRef<Ray>();
    view.add(<>
        <Ray
            ref={ray}
            endArrow
            fromX={() => rect().x() - rect().width()/2 - 100}
            toX={() => rect().x() - rect().width()/2 - 100}
            fromY={() => rect().y() + rect().height()/2}
            toY={() => rect().y() - rect().height()/2}
            stroke={GRAY}
            lineDash={[40, 40]}
            lineWidth={4}
            />
    </>);

    yield* all(
        code().selection(DEFAULT, .3),
        name().filters.saturate(1, .3),
        canary().filters.saturate(.3, .3),
        ray().to.y(rect().y() + rect().height()/2).to.y(rect().y() + rect().height()/2 - 700, .3)
    );

    yield* beginSlide("printf");

    yield* all(
        ray().to.y(ray().to.y() - 300, .3),
        ray().from.y(ray().to.y, .3),
        code().selection(lines(21), .3)
    );

    yield* beginSlide("printf stack");
});
