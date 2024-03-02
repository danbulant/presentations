import {makeProject} from '@motion-canvas/core';

import intro from './scenes/intro?scene';
import program from './scenes/program?scene';
import code from './scenes/code?scene';
import printf from './scenes/printf?scene';

export default makeProject({
  scenes: [intro, program, code, printf],
});
