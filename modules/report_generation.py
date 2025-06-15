from langchain_openai import ChatOpenAI
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config.settings import CHUTES_API_KEY, CHUTES_API_BASE



# Initialize model correctly
llm = ChatOpenAI(
    model_name="deepseek-ai/deepseek-chat",
    openai_api_key=CHUTES_API_KEY,
    openai_api_base=CHUTES_API_BASE,
    temperature=0.7,
    max_tokens=4096
)

def extract_content(response):
    """Safely extract text content from LLM response"""
    if hasattr(response, 'content'):
        return response.content
    elif isinstance(response, dict) and 'content' in response:
        return response['content']
    else:
        return str(response)

def generate_report(data: dict) -> str:
    prompt = f"""
    Create a comprehensive security report based on these findings:
    - Suricata Events: {str(data['suricata_events'][:3])[:3000]}
    - Protocol Analysis: {data['protocol_analysis']}
    - Threat Intel: {data['threat_intel']}
    - Anomalies: {str(data['anomalies'])[:2000]}
    
    Structure:
    - Executive Summary
    - Technical Findings
    - Threat Assessment
    - Recommended Actions
    """
    report = llm.invoke(prompt)
    return extract_content(report)
