import { SqliteDatabaseService } from "../application/sqlite/SqliteDatabaseService.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Compose local snapshot inspection stub (stripped in REA-Argonaut). */
export const createSqliteDatabaseService = (
  _environment: Readonly<NodeJS.ProcessEnv> = process.env,
): SqliteDatabaseService =>
  new SqliteDatabaseService({
    close: async () => {},
    inspect: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "sqlite-database",
          "inspect_sqlite_database",
          "not_configured",
        ),
      ),
  });
