import { RustParityService } from "../application/rustParity/RustParityService.js";
import { RustParityVerifier } from "../native/rustParity/RustParityVerifier.js";

/** Compose bundled closed-loop Rust parity verification. */
export const createRustParityService = (): RustParityService =>
  new RustParityService(new RustParityVerifier());

export const createRustParityTools = createRustParityService;
