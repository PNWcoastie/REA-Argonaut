import {
  aiModelArtifactReportSchema,
  inspectAiModelArtifactInputSchema,
} from "../../domain/aiModel/aiModelArtifact.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Streaming header, tensor topology, and prompt/template inspection for AI model artifacts. */
export const AI_MODEL_TOOL_CONTRACTS = [
  {
    name: "inspect_ai_model_artifact",
    ...toolContractMetadata("inspect_ai_model_artifact"),
    kind: "artifact-provider",
    description:
      "Stream-inspect a local GGUF (.gguf), SafeTensors (.safetensors), ONNX (.onnx), or TensorFlow Lite (.tflite) model artifact in pure TypeScript using bounded file-descriptor slice reads without loading multi-gigabyte weight buffers into memory. Recovers model architecture, quantization/dtype summary, hyperparameters, tensor descriptors (names, dtypes, shapes, byte offsets/lengths), and embedded Jinja chat templates, system prompts, and special control tokens.",
    inputSchema: inspectAiModelArtifactInputSchema,
    outputSchema: evidenceResultOf(aiModelArtifactReportSchema),
    examples: [
      {
        title: "Inspect GGUF or SafeTensors model headers, tensors, and embedded system prompts",
        input: {
          path: "/artifacts/model.gguf",
          max_tensors: 500,
          max_metadata_entries: 500,
          extract_prompts: true,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
