import { GoogleGenAI } from "@google/genai";
import { ScanSession, ScanResult } from "../types";
import { POC_DATABASE } from "../constants";

export const generateSecurityReport = async (session: ScanSession): Promise<string> => {
  if (!process.env.API_KEY) {
    return "API_KEY not found. Please configure the environment to use Gemini analysis.";
  }

  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

  // Filter for vulnerable items
  const vulnerabilities = session.results.filter(r => r.vulnerable);

  if (vulnerabilities.length === 0) {
    return "No vulnerabilities detected. System appears secure based on current test suite.";
  }

  // Enrich data for the prompt
  const vulnDetails = vulnerabilities.map(v => {
    const poc = POC_DATABASE.find(p => p.id === v.pocId);
    return `- [${poc?.severity}] ${poc?.name}: ${v.details}`;
  }).join('\n');

  const prompt = `
    You are a Senior Automotive Cybersecurity Expert.
    
    A vulnerability scan was performed on a vehicle target: "${session.targetName}".
    The following security issues were detected:
    
    ${vulnDetails}
    
    Please provide a comprehensive executive summary report that includes:
    1. An assessment of the overall risk level.
    2. A technical breakdown of the top 3 most critical vulnerabilities found.
    3. Specific remediation or mitigation strategies for these issues.
    4. Recommendations for future security hardening.
    
    Format the response in clean Markdown.
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash-lite',
      contents: prompt,
    });
    return response.text || "Failed to generate report text.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "Error communicating with AI analysis service.";
  }
};