import { ScanSession } from "../types";
import { generateSecurityReport as generateSecurityReportViaBackend } from "./api";

export const generateSecurityReport = async (
  session: ScanSession,
  token: string | null,
  aiSettings?: any
): Promise<string> => {
  return generateSecurityReportViaBackend(session, token, aiSettings);
};
