from langchain_openai import ChatOpenAI

CHUTES_API_KEY = "cpk_b2f19b3b2443491a935341849094244e.0e4c136833ce5488ad2b68a2e843d103.jKtlSsaXnKa1CFQl7BR7UIXa5sfXud8A"
CHUTES_API_BASE = "https://llm.chutes.ai/v1"


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