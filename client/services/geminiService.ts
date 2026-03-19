import { GoogleGenAI } from "@google/genai";
import { ScanSession, ScanResult } from "../types";
import { POC_DATABASE } from "../constants";

export const generateSecurityReport = async (session: ScanSession): Promise<string> => {
  if (!process.env.API_KEY) {
    return "未找到 API_KEY，请配置环境变量后方可使用 Gemini AI 分析功能。";
  }

  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

  // Filter for vulnerable items
  const vulnerabilities = session.results.filter(r => r.vulnerable);

  if (vulnerabilities.length === 0) {
    return "未检测到任何漏洞，根据当前测试套件评估，系统安全状态良好。";
  }

  // Enrich data for the prompt
  const vulnDetails = vulnerabilities.map(v => {
    const poc = POC_DATABASE.find(p => p.id === v.pocId);
    return `- [${poc?.severity}] ${poc?.name}: ${v.details}`;
  }).join('\n');

  const prompt = `
    你是一位资深的汽车网络安全专家，请使用**中文**撰写以下安全分析报告。
    
    已对目标车辆设备 "${session.targetName}" 完成漏洞扫描，检测到如下安全问题：
    
    ${vulnDetails}
    
    请提供一份全面的安全分析报告，内容包括：
    1. 整体风险等级评估。
    2. 对前3个最严重漏洞的技术分析与详细说明。
    3. 针对上述漏洞的具体修复或缓解建议。
    4. 面向未来的安全加固建议。
    
    请使用规范的 Markdown 格式输出报告，所有内容必须使用中文。
  `;

  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash-lite',
      contents: prompt,
    });
    return response.text || "AI 报告生成失败，请稍后重试。";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "与 AI 分析服务通信时发生错误，请检查网络连接或 API Key 配置。";
  }
};