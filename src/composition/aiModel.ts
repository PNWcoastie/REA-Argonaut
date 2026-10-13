import { AiModelArtifactService } from "../application/aiModel/AiModelArtifactService.js";
import { AiModelArtifactInspector } from "../artifacts/aiModel/AiModelArtifactInspector.js";

/** Compose bundled streaming AI model & prompt inspection without external runtimes or processes. */
export const createAiModelArtifactService = (): AiModelArtifactService =>
  new AiModelArtifactService(new AiModelArtifactInspector());

export const createAiModelTools = createAiModelArtifactService;
