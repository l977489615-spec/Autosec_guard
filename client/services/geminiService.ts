import OpenAI from "openai";
import { ScanSession, ScanResult } from "../types";
import { POC_DATABASE } from "../constants";

export const generateSecurityReport = async (session: ScanSession): Promise<string> => {
  if (!process.env.DASHSCOPE_API_KEY && !process.env.API_KEY) {
    return "未找到 API_KEY，请配置环境变量后方可使用千问（Qwen） AI 分析功能。";
  }

  const ai = new OpenAI({ 
    apiKey: process.env.DASHSCOPE_API_KEY || process.env.API_KEY,
    baseURL: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    dangerouslyAllowBrowser: true
  });

  // Filter for vulnerable items
  const vulnerabilities = session.results.filter(r => r.vulnerable);

  if (vulnerabilities.length === 0) {
    return "未检测到任何漏洞，根据当前测试套件评估，系统安全状态良好。";
  }

  // Format date for the report
  const reportDate = session.startTime ? new Date(session.startTime).toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  }) : new Date().toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  // Enrich data for the prompt
  const vulnDetails = vulnerabilities.map(v => {
    const poc = POC_DATABASE.find(p => p.id === v.pocId);
    return `- [${poc?.severity}] ${poc?.name}: ${v.details}`;
  }).join('\n');

  const prompt = `
    你是一位资深的汽车网络安全专家，请使用**中文**撰写以下安全分析报告。
    
    针对目标车辆设备 "${session.targetName}" 完成了漏洞扫描。
    
    报告日期：${reportDate}
    报告撰写人：BIOS安全团队
    
    检测到如下安全问题：
    
    ${vulnDetails}
    
    请提供一份全面的安全分析报告，内容包括：
    1. 报告页眉（包含：报告名称、针对目标、扫描日期、撰写人）。
    2. 整体风险等级评估。
    3. 对前3个最严重漏洞的技术分析与详细说明。
    4. 针对上述漏洞的具体修复或缓解策略。
    5. 面向未来的安全加固建议。
    
    请使用规范的 Markdown 格式输出报告，所有内容必须使用中文。
    注意：请务必在报告开头准确显示上述提供的“报告日期”和“报告撰写人”，不要使用占位符。
  `;

  try {
    const response = await ai.chat.completions.create({
      model: 'qwen-max',
      messages: [{role: 'user', content: prompt}],
    });
    return response.choices[0].message.content || "AI 报告生成失败，请稍后重试。";
  } catch (error) {
    console.error("Qwen API Error:", error);
    return "与千问（Qwen）大模型通信时发生错误，请检查网络连接或 API Key 配置。";
  }
};