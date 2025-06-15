# suricata_fastlog_analyzer.py

import os
import re
import asyncio
from typing import List, Dict
from langchain_openai import ChatOpenAI

# Add parent directory to path (for CHUTES settings)
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config.settings import CHUTES_API_KEY, CHUTES_API_BASE

# Configuration
CHUNK_SIZE = 5  # Number of alerts to process at once

def parse_fastlog(suricata_output_dir: str) -> List[Dict]:
    """Parse Suricata fast.log file into structured alerts"""
    fastlog_path = os.path.join(suricata_output_dir, "fast.log")
    alerts = []

    # Pattern to match Suricata fast.log entries
    pattern = re.compile(
        r'(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+'
        r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<msg>.*?)\s+\[\*\*\]\s+'
        r'\[Classification:\s*(?P<classification>.*?)\]\s+\[Priority:\s*(?P<priority>\d+)\]\s+'
        r'\{(?P<proto>\w+)\}\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+'
        r'(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)'
    )

    if os.path.exists(fastlog_path):
        with open(fastlog_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                match = pattern.search(line)
                if match:
                    alert = match.groupdict()
                    alert['priority'] = int(alert['priority'])
                    alerts.append(alert)
                else:
                    print(f"Pattern didn't match line: {line}")

    return alerts

def chunk_alerts(alerts: List[Dict], chunk_size: int) -> List[List[Dict]]:
    """Split alerts into chunks for processing"""
    return [alerts[i:i + chunk_size] for i in range(0, len(alerts), chunk_size)]

async def analyze_chunk(chunk: List[Dict], llm: ChatOpenAI) -> str:
    """Analyze a chunk of alerts with LLM"""
    prompt = f"""Analyze these Suricata alerts and identify security threats.
For each alert or related group, describe the potential threat and its severity.

Alerts:
{chunk}

Provide your analysis in clear, concise paragraphs:"""
    
    try:
        response = await llm.ainvoke(prompt)
        return response.content
    except Exception as e:
        return f"Analysis failed: {str(e)}"

async def process_alerts(alerts: List[Dict]) -> List[str]:
    """Process all alerts through LLM in parallel chunks"""
    llm = ChatOpenAI(
        model="deepseek-ai/DeepSeek-V3-0324",
        openai_api_key=CHUTES_API_KEY,
        openai_api_base=CHUTES_API_BASE,
        temperature=0.3,
        max_tokens=1024,
        request_timeout=30
    )

    chunks = chunk_alerts(alerts, CHUNK_SIZE)
    tasks = [analyze_chunk(chunk, llm) for chunk in chunks]
    results = []

    for future in asyncio.as_completed(tasks):
        try:
            result = await future
            results.append(result)
        except Exception as e:
            results.append(f"Chunk processing failed: {str(e)}")

    return {"anomalies": results}

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Suricata fast.log analyzer")
    parser.add_argument("suricata_output_dir", help="Path to Suricata output directory")
    args = parser.parse_args()

    # Parse logs
    alerts = parse_fastlog(args.suricata_output_dir)
    print(f"Found {len(alerts)} alerts in fast.log")

    # Process with LLM
    results = asyncio.run(process_alerts(alerts))

    # Print results
    print("\n=== Analysis Results ===")
    for i, result in enumerate(results, 1):
        print(f"\nChunk {i} Analysis:")
        print(result)

if __name__ == "__main__":
    main()
