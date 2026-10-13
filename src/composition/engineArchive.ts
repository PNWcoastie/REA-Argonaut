import { EngineArchiveService } from "../application/engineArchive/EngineArchiveService.js";
import { EngineArchiveInspector } from "../artifacts/engineArchive/EngineArchiveInspector.js";

/** Compose bundled Unity IL2CPP & Godot .pck archive inspection without external runtimes or processes. */
export const createEngineArchiveService = (): EngineArchiveService =>
  new EngineArchiveService(new EngineArchiveInspector());

export const createEngineArchiveTools = createEngineArchiveService;
