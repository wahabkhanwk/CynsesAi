from langchain_openai import ChatOpenAI
from typing import Dict, List
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config.settings import CHUTES_API_KEY, CHUTES_API_BASE

def analyze_protocols(logs: Dict[str, List[str]], rag_context: str) -> dict:
    """Perform generic protocol analysis using LLM on all .log files"""
    log_samples = {}

    for log_name, lines in logs.items():
        # Skip empty or header-only logs
        if len(lines) > 1:
            # Take up to 10 lines after header for each log
            log_samples[log_name] = lines[1:]
        elif lines:
            log_samples[log_name] = lines

    prompt = f"""
    Analyze the following Zeek log samples and identify any suspicious or notable patterns.
    ### Log Samples:
    {str(log_samples)[:3000]}
    ### Security Context:
    {rag_context}
    """
    llm = ChatOpenAI(
        model="deepseek-ai/DeepSeek-V3-0324",
        openai_api_key=CHUTES_API_KEY,
        openai_api_base=CHUTES_API_BASE,
        temperature=0.7,
        max_tokens=1024
    )
    analysis = llm.invoke(prompt)
    return {
        "raw": log_samples,
        "llm_analysis": analysis.content if hasattr(analysis, 'content') else str(analysis)
    }
