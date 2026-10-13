import { PythonFrozenBinaryService } from "../application/pythonFrozen/PythonFrozenBinaryService.js";
import { PythonFrozenBinaryInspector } from "../native/pythonFrozen/PythonFrozenBinaryInspector.js";

/** Compose bundled offline Frozen Python & .pyc inspection without external runtimes or processes. */
export const createPythonFrozenBinaryService = (): PythonFrozenBinaryService =>
  new PythonFrozenBinaryService(new PythonFrozenBinaryInspector());
