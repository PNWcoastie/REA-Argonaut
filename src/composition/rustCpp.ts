import { RustCppBinaryService } from "../application/rustCpp/RustCppBinaryService.js";
import { RustCppBinaryInspector } from "../native/rustCpp/RustCppBinaryInspector.js";

/** Compose bundled offline Rust & C++ binary inspection without external toolchains or processes. */
export const createRustCppBinaryService = (): RustCppBinaryService =>
  new RustCppBinaryService(new RustCppBinaryInspector());
