from langchain_openai import ChatOpenAI
from typing import Dict, List

def analyze_protocols(logs: Dict[str, List[str]], rag_context: str) -> dict:
    """Perform protocol analysis using LLM"""
    protocols = {
        "connections": [],
        "http_requests": [],
        "dns_queries": []
    }

    for log_name, lines in logs.items():
        if "conn.log" in log_name:
            protocols["connections"] = lines[1:11]
        elif "http.log" in log_name:
            for line in lines[1:6]:
                fields = line.split("\t")
                if len(fields) > 9:
                    protocols["http_requests"].append(fields[9])
        elif "dns.log" in log_name:
            for line in lines[1:6]:
                fields = line.split("\t")
                if len(fields) > 9:
                    protocols["dns_queries"].append(fields[9])

    prompt = f"""
    Analyze network activity from Zeek logs and identify suspicious patterns.
    ### Protocol Summary:
    {str(protocols)[:2000]}
    ### Security Context:
    {rag_context}
    """
    llm = ChatOpenAI(model="deepseek-ai/DeepSeek-V3-0324", temperature=0.7, max_tokens=1024)
    analysis = llm.invoke(prompt)
    return {
        "raw": protocols,
        "llm_analysis": analysis.content if hasattr(analysis, 'content') else str(analysis)
    }
