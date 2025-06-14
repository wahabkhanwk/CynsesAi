from langchain_openai import ChatOpenAI

def detect_anomalies(data: dict, rag_context: str) -> dict:
    prompt = f"""
    Analyze this network data for security anomalies:
    {str(data)[:3000]}
    Suricata Documentation Context:
    {rag_context}
    Identify potential threats and rate severity (1-10).
    """
    llm = ChatOpenAI(model="deepseek-ai/DeepSeek-V3-0324", temperature=0.7, max_tokens=1024)
    analysis = llm.invoke(prompt)
    return {
        "anomalies": [{"description": analysis.content, "severity": 7}]
    }
