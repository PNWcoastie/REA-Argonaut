import { z } from "zod";
import type { ProviderIdentity } from "../../application/AnalysisProvider.js";

/** Provider identity committed by the pure-TS streaming AI model & prompt inspector. */
export const AI_MODEL_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "argon-ai-model-forensics",
  name: "ArgonZeroG Streaming AI Model & Prompt Inspector",
  version: "1.0.0",
});

export const aiModelFormatSchema = z
  .enum(["gguf", "safetensors", "onnx", "tflite"])
  .describe("Detected AI model serialization format.");

export type AiModelFormat = z.infer<typeof aiModelFormatSchema>;

export const inspectAiModelArtifactInputSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .describe(
        "Absolute filesystem path to the local .gguf, .safetensors, .onnx, or .tflite model artifact.",
      ),
    max_tensors: z
      .number()
      .int()
      .min(1)
      .max(10_000)
      .default(500)
      .describe(
        "Maximum number of tensor descriptors to return in the report (default 500).",
      ),
    max_metadata_entries: z
      .number()
      .int()
      .min(1)
      .max(5_000)
      .default(500)
      .describe(
        "Maximum number of key-value metadata entries to return (default 500).",
      ),
    extract_prompts: z
      .boolean()
      .default(true)
      .describe(
        "Whether to extract embedded Jinja chat templates, system prompts, and control token definitions (default true).",
      ),
  })
  .strict();

export type InspectAiModelArtifactInput = z.infer<
  typeof inspectAiModelArtifactInputSchema
>;

export const aiModelPromptTemplateSchema = z
  .object({
    key: z
      .string()
      .min(1)
      .describe(
        "Metadata key or section where the prompt/template was discovered (e.g., 'tokenizer.chat_template').",
      ),
    kind: z
      .enum(["chat_template", "system_prompt", "instruction_template", "doc_string"])
      .describe("Classification of the extracted prompt or template."),
    template_text: z
      .string()
      .describe("Full un-truncated Jinja or text prompt template."),
    detected_special_tokens: z
      .array(z.string())
      .describe(
        "Special control/role tokens referenced inside the template (e.g., '<|im_start|>', '<|begin_of_text|>', '[INST]').",
      ),
  })
  .strict();

export type AiModelPromptTemplate = z.infer<typeof aiModelPromptTemplateSchema>;

export const aiModelTensorDescriptorSchema = z
  .object({
    name: z.string().min(1).describe("Tensor identifier (e.g., 'blk.0.attn_q.weight')."),
    dtype: z
      .string()
      .min(1)
      .describe("Storage data/quantization type (e.g., 'Q4_K', 'F16', 'BF16', 'F32', 'I8')."),
    shape: z
      .array(z.number().int().nonnegative())
      .describe("Tensor dimension sizes."),
    byte_offset: z
      .number()
      .int()
      .nonnegative()
      .nullable()
      .describe("Byte offset of tensor weight payload within the file or data section, if available."),
    byte_length: z
      .number()
      .int()
      .nonnegative()
      .nullable()
      .describe("Byte length of the tensor weight payload, if available."),
  })
  .strict();

export type AiModelTensorDescriptor = z.infer<
  typeof aiModelTensorDescriptorSchema
>;

export const aiModelArtifactReportSchema = z
  .object({
    path: z.string().min(1),
    sha256_header: z
      .string()
      .regex(/^[0-9a-f]{64}$/)
      .describe(
        "SHA-256 digest of the leading header slice (up to 1 MiB) for fast streaming identification without reading multi-GB weight buffers.",
      ),
    size_bytes: z.number().int().nonnegative(),
    header_bytes_read: z
      .number()
      .int()
      .nonnegative()
      .describe(
        "Total bytes read from disk via streaming file descriptor during header/metadata inspection.",
      ),
    format: aiModelFormatSchema,
    format_version: z.string().min(1),
    endianness: z.enum(["little", "big"]),
    architecture: z
      .string()
      .nullable()
      .describe("Detected model architecture family (e.g., 'llama', 'gemma3', 'qwen2', 'onnx-graph')."),
    model_name: z.string().nullable(),
    quantization_or_dtype: z
      .string()
      .nullable()
      .describe("Primary quantization or tensor dtype summary (e.g., 'Q4_K_M', 'BF16', 'F16')."),
    extracted_prompts: z.array(aiModelPromptTemplateSchema),
    metadata: z
      .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
      .describe("Flattened scalar model metadata and hyperparameters."),
    tensor_count: z
      .number()
      .int()
      .nonnegative()
      .describe("Total number of tensors declared in the model artifact."),
    tensors: z.array(aiModelTensorDescriptorSchema),
  })
  .strict();

export type AiModelArtifactReport = z.infer<typeof aiModelArtifactReportSchema>;
