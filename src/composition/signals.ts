import { SignalRecordingService } from "../application/signals/SignalRecordingService.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

export const createSignalRecordingService = (
  _environment: Readonly<NodeJS.ProcessEnv> = process.env,
): SignalRecordingService =>
  new SignalRecordingService({
    close: async () => {},
    decode: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "signal-recording",
          "decode_signal_recording",
          "not_configured",
        ),
      ),
  });
