import {makeProject} from '@motion-canvas/core';

import functionCall from './scenes/function-run?scene';
import overwritingLocals from './scenes/overwriting-locals?scene';

export default makeProject({
  scenes: [functionCall, overwritingLocals],
});
