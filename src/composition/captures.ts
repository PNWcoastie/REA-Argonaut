import { PacketCaptureService } from "../application/captures/PacketCaptureService.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

export const createPacketCaptureService = (
  _environment: Readonly<NodeJS.ProcessEnv> = process.env,
): PacketCaptureService =>
  new PacketCaptureService({
    close: async () => {},
    inspect: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "packet-capture",
          "inspect_packet_capture",
          "not_configured",
        ),
      ),
  });
