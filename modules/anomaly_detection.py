from langchain_openai import ChatOpenAI
import os
import json
from config.settings import CHUTES_API_KEY, CHUTES_API_BASE

def detect_anomalies(suricata_output_dir: str, rag_context: str) -> dict:
    eve_path = os.path.join(suricata_output_dir, "eve.json")
    fastlog_path = os.path.join(suricata_output_dir, "fast.log")

    eve_events = []
    if os.path.exists(eve_path):
        with open(eve_path) as f:
            for line in f:
                try:
                    eve_events.append(json.loads(line))
                except Exception:
                    continue

    fastlog_lines = []
    if os.path.exists(fastlog_path):
        with open(fastlog_path) as f:
            fastlog_lines = [line.strip() for line in f if line.strip()]

    prompt = f"""
    Analyze the following Suricata outputs for security anomalies:

    --- eve.json events ---
    {json.dumps(eve_events[1:], indent=2)}

    --- fast.log lines ---
    {fastlog_lines[1:]}

    Suricata Documentation Context:
    {rag_context}

    Identify potential threats and rate severity (1-10).
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
        "anomalies": [{"description": analysis.content if hasattr(analysis, "content") else str(analysis), "severity": 7}]
    }
