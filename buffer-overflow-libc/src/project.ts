import {makeProject} from '@motion-canvas/core';

import intro from './scenes/intro?scene';
import program from './scenes/program?scene';
import code from './scenes/code?scene';
import printf from './scenes/printf?scene';
import script from './scenes/script?scene';

export default makeProject({
  scenes: [intro, program, code, printf, script],
});

window.addEventListener("keydown", (e) => {
  if (e.key === "PageDown") {
    // send fake space key
    const event = new KeyboardEvent("keydown", {
      key: " ",
      code: "Space",
      keyCode: 32,
      which: 32
    });
    document.dispatchEvent(event);
  } else if (e.key === "PageUp") {
    // send fake arrow left key
    const event = new KeyboardEvent("keydown", {
      key: "ArrowLeft",
      code: "ArrowLeft",
      keyCode: 37,
      which: 37
    });
    document.dispatchEvent(event);
  }
})