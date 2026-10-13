import { z } from "zod";

import {
  compareManagedMembers,
  managedMemberComparisonResultSchema,
  type CompareManagedMembersInput,
} from "../../domain/managed/managedMemberComparison.js";
import { parseManagedMemberEvidence } from "../../domain/managed/managedMemberComparisonMatch.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import type { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisProtocolError,
} from "../../domain/analysisErrorCore.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { jsonValueSchema } from "../../domain/jsonValue.js";
import { parseBinaryTarget } from "../BinaryTargetResolver.js";
import { err, ok, type Result } from "../../domain/result.js";
import { MANAGED_WORKFLOW_PROVIDER } from "../InvestigationProviders.js";
import { workflowInputError } from "../workflowInputError.js";

/** Compare managed members from input parsed by a trusted adapter. */
export const compareManagedMembersEvidenceValidated = (
  input: CompareManagedMembersInput,
): Result<Evidence, AnalysisError> => {
  const operation = "compare_managed_members";
  try {
    const left = parseManagedMemberEvidence(input.left);
    const right = parseManagedMemberEvidence(input.right);
    const result = compareManagedMembers(
      { evidenceId: left.evidenceId, result: left.result },
      { evidenceId: right.evidenceId, result: right.result },
    );
    return ok(createManagedMemberComparisonEvidence(input, result));
  } catch (cause: unknown) {
    return workflowFailure(operation, cause);
  }
};

interface ManagedMemberComparisonPathDependencies {
  readonly resolveTarget: typeof parseBinaryTarget;
  readonly readSnapshot?: (
    path: string,
    operation: string,
    options?: { readonly resources?: ArtifactResourceScope },
  ) => Promise<{ readonly bytes: Buffer; readonly sha256: string }>;
}

/** Inspect two local PE artifacts and return one derived comparison Evidence. */
export const compareManagedMemberPaths = async (
  input: {
    readonly leftPath: string;
    readonly rightPath: string;
  },
  _dependencies: Partial<ManagedMemberComparisonPathDependencies> = {},
  _resources?: ArtifactResourceScope,
): Promise<Result<Evidence, AnalysisError>> => {
  void input;
  return err(
    new AnalysisCapabilityUnavailableError(
      "managed-static",
      "compare_managed_members",
      "not_configured",
    ),
  );
};

const createManagedMemberComparisonEvidence = (
  parameters: Pick<CompareManagedMembersInput, "left" | "right">,
  result: z.infer<typeof managedMemberComparisonResultSchema>,
  sourcePaths?: { readonly leftPath: string; readonly rightPath: string },
): Evidence =>
  createEvidence(undefined, MANAGED_WORKFLOW_PROVIDER, {
    predicateType: "rea.managed-member-comparison",
    operation: "compare_managed_members",
    parameters: {
      left_evidence_id: parameters.left.evidence_id,
      right_evidence_id: parameters.right.evidence_id,
      ...(sourcePaths === undefined
        ? {}
        : {
            left_path: sourcePaths.leftPath,
            right_path: sourcePaths.rightPath,
          }),
    },
    result: jsonValueSchema.parse(result),
    rawResult: null,
    confidence: "inferred",
    authority: "analyst-inference",
    environment: null,
    limitations: result.limitations,
    locations:
      sourcePaths === undefined
        ? []
        : [
            { kind: "artifact-path", path: sourcePaths.leftPath },
            { kind: "artifact-path", path: sourcePaths.rightPath },
          ],
    evidenceLinks: result.evidence_links,
  });

const workflowFailure = (
  operation: string,
  cause: unknown,
  partialEvidence?: Evidence,
): Result<never, AnalysisError> => {
  const failure =
    cause instanceof AnalysisError
      ? cause
      : cause instanceof z.ZodError || cause instanceof TypeError
        ? workflowInputError(operation, cause)
        : new AnalysisProtocolError(
            "Managed member comparison produced an invalid result",
            { cause },
          );
  return err(
    partialEvidence === undefined
      ? failure
      : failure.retainPartialObservation(partialEvidence),
  );
};
