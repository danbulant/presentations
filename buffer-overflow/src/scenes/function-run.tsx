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
  const code = createRef<CodeBlock>();
  const rectLayout = createRef<Layout>();
  const rect = createRef<Rect>();
  const innerLayout = createRef<Layout>();
  const prevFrameRect = createRef<Rect>();
  const currentFrameRect = createRef<Rect>();
  const topLayout = createRef<Layout>();
  const rbp = createSignal(0);
  const rbpRay = createRef<Ray>();
  const rsp = createSignal(0);
  const rspRay = createRef<Ray>();

  rbp(100);
  rsp(200);

  view.add(
    <Layout ref={topLayout} justifyContent={'center'} alignItems={'center'} layout gap={5} padding={5} width={view.width} height={view.height} />
  );
  topLayout().add(
    <Layout ref={rectLayout} justifyContent={'center'} direction="column" grow={1} padding={15}>
      <Rect
        ref={rect}
        height={800}
        width={500}
        lineWidth={4}
        stroke={GRAY}
        >
          <Layout
            ref={innerLayout}
            direction="column"
            >
              <Rect
                ref={prevFrameRect}
                height={100}
                width={500}
                fill={GREEN}
                stroke={GRAY}
                lineWidth={4}>
                  <Txt width={500} textAlign={'center'} lineHeight={100} fill={BLACK} text="Previous frame" fontFamily={'monospace'} />
              </Rect>
              <Rect
                ref={currentFrameRect}
                height={100}
                width={500}
                fill={RED}
                stroke={GRAY}
                lineWidth={4}>
                  <Txt width={500} textAlign={'center'} lineHeight={100} fill={BLACK} text="Current frame" fontFamily={'monospace'} />
              </Rect>
          </Layout>
      </Rect>
    </Layout>
  );

  view.add(
    <>
      <Ray
        ref={rbpRay}
        toX={0}
        fromX={100}
        endArrow
        lineWidth={4}
        stroke={GRAY}
      >
        <Txt
          text="RBP"
          x={60}
          width={80}
          y={-20}
          fill={WHITE}
          fontFamily={'monospace'}
          fontSize={20}
          lineHeight={20}
          textAlign={'center'}
        />
      </Ray>
      <Ray
        ref={rspRay}
        toX={0}
        fromX={100}
        endArrow
        lineWidth={4}
        stroke={GRAY}
      >
        <Txt
          text="RSP"
          x={60}
          width={80}
          y={-20}
          fill={WHITE}
          fontFamily={'monospace'}
          fontSize={20}
          lineHeight={20}
          textAlign={'center'}
        />
      </Ray>
    </>
  );

  yield topLayout().insert(
    <CodeBlock
    ref={code}
    language='asm'
    grow={1}
    code={`
    main:
      PUSH RBP
      MOV RBP,RSP
      PUSH 0x7
      MOV R9D,0x6
      MOV R8D,0x5
      MOV ECX,0x4
      MOV EDX,0x3
      MOV ESI,0x2
      MOV EDI,0x1
      CALL test
      ADD RSP,0x8

    test:
      PUSH RBP
      MOV RBP, RSP
      SUB RSP, 0x8
      MOV [RBP - 0x8], [RBP + 0x8]
      ADD [RBP - 0x8], 1
      MOV RSP, RBP
      POP RBP
      RET
    `}
    fontSize={30}
  />,0);

  const rbpPosition = createSignal(() =>
    rect().absolutePosition()
      .addX(rect().width() / 2)
      .addY(-rect().height() / 2)
      .addY(rbp())
  );

  rbpRay().absolutePosition(rbpPosition);

  const rspPosition = createSignal(() =>
    rect().absolutePosition()
      .addX(rect().width() / 2)
      .addY(-rect().height() / 2)
      .addY(rsp())
  );

  rspRay().absolutePosition(rspPosition);

  let rectRefs: Reference<Rect>[] = [];
  function* insertRect(text: string, changeRsp = true) {
    let rectRef = createRef<Rect>();
    rectRefs.push(rectRef);
    innerLayout().add(
      <Rect
        ref={rectRef}
        height={0}
        width={500}
        fill={BLUE}
        stroke={GRAY}
        lineWidth={4}>
          <Txt width={500} textAlign={'center'} lineHeight={100} fill={BLACK} text={text} fontFamily={'monospace'} />
      </Rect>
    );

    yield* all(
      changeRsp && rsp(rsp() + 100, 1),
      rectRef().height(100, 1),
    );
  }

  yield* beginSlide('initial slide');

  // PUSH 0x7

  yield* code().selection(lines(3), 1);
  yield* insertRect('0x7');

  yield* beginSlide('PUSH 0x7');

  // CALL test

  yield* code().selection(lines(10), 1);
  yield* insertRect('RIP');

  yield* beginSlide('CALL test');

  // PUSH RBP

  yield* code().selection(lines(14), 1);
  yield* insertRect('RBP');

  yield* beginSlide('PUSH RBP');

  // MOV RBP,RSP

  yield* code().selection(lines(15), 1);
  yield* rbp(rsp(), 1);

  yield* beginSlide('MOV RBP,RSP');

  // SUB RSP, 0x8

  yield* code().selection(lines(16), 1);
  yield* rsp(rsp() + 100, 1);

  yield* beginSlide('SUB RSP, 0x8');

  // MOV [RBP - 0x8], [RBP + 0x8]

  yield* code().selection(lines(17), 1);
  yield* insertRect('0x7', false);

  yield* beginSlide('MOV [RBP - 0x8], [RBP + 0x8]');

  // ADD [RBP - 0x8], 1

  let textRef = rectRefs[rectRefs.length - 1]().findFirst((n) => n instanceof Txt) as Txt;
  yield* code().selection(lines(18), 1);
  textRef.text('0x8');

  yield* beginSlide('ADD [RBP - 0x8], 1');

  // MOV RSP, RBP

  yield* code().selection(lines(19), 1);
  rectRefs.pop()().remove();
  yield* rsp(rbp(), 1);

  yield* beginSlide('MOV RSP, RBP');

  // POP RBP

  yield* code().selection(lines(20), 1);
  yield* rbp(100, 1);
  rectRefs.pop()().remove();
  yield* rsp(rsp() - 100, 1);

  yield* beginSlide('POP RBP');

  // RET

  yield* code().selection(lines(21), 1);
  yield* rsp(rsp() - 100, 1);
  rectRefs.pop()().remove();

  yield* beginSlide('RET');

  // ADD RSP,0x8

  yield* code().selection(lines(11), 1);
  yield* rsp(rsp() - 100, 1);

  yield* beginSlide('ADD RSP,0x8');
});
