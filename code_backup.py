import os
import json
import subprocess
from typing import TypedDict, Annotated, Dict, List
from langgraph.graph import StateGraph, END
#from langchain_community.llms import Ollama
from langchain_openai import ChatOpenAI
from langchain_community.vectorstores import Chroma
#from langchain_community.embeddings import OllamaEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import WebBaseLoader
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from pathlib import Path
from suricata_parser import run_suricata
from langchain_core.messages import BaseMessage
import requests
from diskcache import Cache
os.environ["USER_AGENT"] = "CynsesAI-PCAP-Analyzer/1.0"

# Initialize diskcache Cache
cache = Cache("./cache_dir")

# Configuration
USE_OLLAMA = False  # Set to False for API-based LLM
PCAP_FILE = "/Users/macbook/Desktop/CynsesAI/GoldenEye.pcap"  # Update with your PCAP file pat
SURICATA_DOCS_URL = "https://suricata.readthedocs.io/en/latest/"

# Define the analysis state
class AnalysisState(TypedDict):
    pcap_path: str
    suricata_events: List[Dict]
    zeek_logs: Dict
    protocol_analysis: Dict
    threat_intel: Dict
    anomalies: List[Dict]
    visualization_data: Dict
    report: str
    rag_context: str

CHUTES_API_KEY = "cpk_b2f19b3b2443491a935341849094244e.0e4c136833ce5488ad2b68a2e843d103.jKtlSsaXnKa1CFQl7BR7UIXa5sfXud8A"
CHUTES_API_BASE = "https://llm.chutes.ai/v1"

# Initialize LLM
# Initialize LLM
if USE_OLLAMA:
    llm = OllamaLLM(model="llama3.2")
    embeddings = OllamaEmbeddings(model="llama3.2")
else:
    llm = ChatOpenAI(
        model="deepseek-ai/DeepSeek-V3-0324",
        openai_api_key=CHUTES_API_KEY,
        openai_api_base=CHUTES_API_BASE,
        temperature=0.7,
        max_tokens=1024,
    )
    embeddings = None  
# ------------------------
# Tool Wrapper Functions
# ------------------------


@cache.memoize()
def run_suricata(pcap_path: str) -> List[Dict]:
    """Run Suricata on PCAP file and parse results"""
    output_dir = "suricata_output"
    os.makedirs(output_dir, exist_ok=True)

# Paths - update these as needed
    SURICATA_CONFIG = "/opt/homebrew/etc/suricata/suricata.yaml"
    PCAP_PATH = "/Users/macbook/Desktop/CynsesAI/GoldenEye.pcap"
    OUTPUT_DIR = "suricata_output"

# Execute Suricata without the --set parameter
    subprocess.run([
        "suricata",
        "-c", SURICATA_CONFIG,
        "-r", PCAP_PATH,
        "-l", OUTPUT_DIR
        ], check=True)
    # Parse results
    events = []
    eve_path = os.path.join(output_dir, "eve.json")
    if os.path.exists(eve_path):
        with open(eve_path) as f:
            for line in f:
                events.append(json.loads(line))
    return events

@cache.memoize()
def run_zeek(pcap_path: str) -> Dict:
    """Run Zeek on PCAP file and parse logs"""
    output_dir = "zeek_output"
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Execute Zeek with proper error handling
    try:
        result = subprocess.run(
            ["zeek", "-C", "-r", pcap_path, f"Log::default_logdir={output_path.absolute()}"],
            check=True,
            capture_output=True,
            text=True
        )
        # Print warnings but continue
        if result.stderr:
            print(f"⚠️ Zeek warnings: {result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Zeek failed: {e.stderr}")
        return {"error": f"Zeek execution failed: {e.stderr}"}
    
    # Parse logs with error handling
    logs = {}
    for log_file in output_path.glob("*.log"):
        try:
            with log_file.open() as f:
                logs[log_file.name] = f.readlines()
        except Exception as e:
            print(f"❌ Error reading {log_file}: {str(e)}")
            logs[log_file.name] = [f"Error reading log: {str(e)}"]
    
    return logs

@cache.memoize()
def real_threat_intel(ip: str) -> Dict:
    # Example with AbuseIPDB
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": "99b0c8552352c73ac74739cf496a06d8e006ff2353d6b21d5d9a6e07f616f3d9dcc507b1eade1cca", "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    return response.json()

# ------------------------
# RAG Setup - Suricata Documentation
# ------------------------

def setup_suricata_rag() -> Chroma:
    """Create vector store with Suricata documentation"""
    loader = WebBaseLoader(SURICATA_DOCS_URL)
    docs = loader.load()
    
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000, chunk_overlap=200
    )
    documents = text_splitter.split_documents(docs)
    
    return Chroma.from_documents(
        documents=documents, 
        embedding=embeddings or OllamaEmbeddings(model="llama3.2")
    )

# Initialize RAG vector store
suricata_vectorstore = setup_suricata_rag()

@cache.memoize()
def retrieve_suricata_docs(query: str) -> str:
    """Retrieve relevant Suricata documentation"""
    docs = suricata_vectorstore.similarity_search(query, k=3)
    return "\n\n".join([d.page_content for d in docs])

# ------------------------
# LangGraph Node Functions
# ------------------------

def initialize_analysis(state: AnalysisState) -> Dict:
    """Node 1: Initialize analysis"""
    print("🚀 Starting PCAP analysis workflow")
    return {
        "pcap_path": state["pcap_path"],
        "rag_context": retrieve_suricata_docs("PCAP analysis with Suricata")
    }

def run_suricata_node(state: AnalysisState) -> Dict:
    """Node 2: Run Suricata analysis"""
    print("🔍 Running Suricata on PCAP...")
    events = run_suricata(state["pcap_path"])
    
    # Retrieve relevant docs for detected events
    if events:
        event_types = ", ".join(set(e.get("event_type", "") for e in events))
        rag_context = retrieve_suricata_docs(
            f"Suricata event types: {event_types}"
        )
    else:
        rag_context = "No Suricata events detected"
    
    return {
        "suricata_events": events,
        "rag_context": rag_context
    }

def run_zeek_node(state: AnalysisState) -> Dict:
    """Node 3: Run Zeek analysis"""
    print("🕵️ Running Zeek on PCAP...")
    return {"zeek_logs": run_zeek(state["pcap_path"])}

#def protocol_analysis_node(state: AnalysisState) -> Dict:
    """Node 4: Perform protocol analysis"""
    print("📡 Analyzing network protocols...")
    
    # Extract protocol info from Zeek logs
    # Extract protocol info from Zeek logs
    protocols = {
    "connections": [],
    "http_requests": [],
    "dns_queries": []
    }

    for log_name, lines in state["zeek_logs"].items():
        if "conn.log" in log_name:
            protocols["connections"] = lines[:10]  # Sample connections
        elif "http.log" in log_name:
            protocols["http_requests"] = [line.split("\t")[9] for line in lines[:5]]  # URI sample
        elif "dns.log" in log_name:
            protocols["dns_queries"] = [line.split("\t")[9] for line in lines[:5]]  # Query sample
    # Add LLM-enhanced analysis
    prompt = f"""
    ## Network Protocol Analysis Task
    Analyze network activity from Zeek logs and identify suspicious patterns.

    ### Protocol Summary:
    {json.dumps(protocols)[:2000]}

    ### Security Context:
    {state['rag_context']}

    ### Analysis Instructions:
    1. Identify protocol distribution and unusual ports
    2. Detect abnormal connection patterns
    3. Flag suspicious HTTP requests or DNS queries
    4. Correlate findings with Suricata alerts
    5. Provide concise security assessment
    """
    
    # Handle different LLM response types
    response = llm.invoke(prompt)
    
    # Check if response has 'content' attribute or is plain string
    if hasattr(response, 'content'):
        analysis = response.content
    elif isinstance(response, str):
        analysis = response
    else:
        # Fallback: convert to string
        analysis = str(response)
    
    return {
        "protocol_analysis": {
            "raw": protocols,
            "llm_analysis": analysis
        }
    }
def protocol_analysis_node(state: AnalysisState) -> Dict:
    """Node 4: Perform protocol analysis"""
    print("📡 Analyzing network protocols...")
    
    # Extract protocol info from Zeek logs
    protocols = {
        "connections": [],
        "http_requests": [],
        "dns_queries": []
    }
    
    for log_name, lines in state["zeek_logs"].items():
        if "conn.log" in log_name:
            # Skip header line and take sample
            protocols["connections"] = lines[1:11] if len(lines) > 1 else lines
            
        elif "http.log" in log_name:
            # Extract URIs with safety checks
            for line in lines[1:6]:  # Skip header, take first 5 data lines
                fields = line.split("\t")
                if len(fields) > 9:
                    protocols["http_requests"].append(fields[9])
                elif fields:  # Still add something if fields exist
                    protocols["http_requests"].append(fields[0])
                    
        elif "dns.log" in log_name:
            # Extract queries with safety checks
            for line in lines[1:6]:  # Skip header, take first 5 data lines
                fields = line.split("\t")
                if len(fields) > 9:
                    protocols["dns_queries"].append(fields[9])
                elif fields:  # Still add something if fields exist
                    protocols["dns_queries"].append(fields[0])
    
    # Build analysis prompt
    prompt = f"""
    ## Network Protocol Analysis Task
    Analyze network activity from Zeek logs and identify suspicious patterns.
    
    ### Protocol Summary:
    {json.dumps(protocols)[:2000]}
    
    ### Security Context:
    {state['rag_context']}
    
    ### Analysis Instructions:
    1. Identify protocol distribution and unusual ports
    2. Detect abnormal connection patterns
    3. Flag suspicious HTTP requests or DNS queries
    4. Correlate findings with Suricata alerts
    5. Provide concise security assessment
    """
    
    try:
        # Get and handle LLM response
        response = llm.invoke(prompt)
        
        if hasattr(response, 'content'):
            analysis = response.content
        elif isinstance(response, str):
            analysis = response
        else:
            analysis = str(response)
            
    except Exception as e:
        analysis = f"⚠️ Analysis failed: {str(e)}"
        print(f"LLM invocation error: {str(e)}")
    
    return {
        "protocol_analysis": {
            "raw": protocols,
            "llm_analysis": analysis
        }
    }
def threat_intel_node(state: AnalysisState) -> Dict:
    """Node 5: Threat intelligence enrichment"""
    print("🌐 Enriching with threat intelligence...")
    
    # Extract unique IPs from Suricata events
    ips = set()
    for event in state["suricata_events"]:
        if "src_ip" in event:
            ips.add(event["src_ip"])
        if "dest_ip" in event:
            ips.add(event["dest_ip"])
    
    # Get threat intel for each IP
    threat_data = {ip: real_threat_intel(ip) for ip in ips}
    
    # Add LLM-enhanced analysis
    prompt = f"""
    Analyze this threat intelligence data:
    {json.dumps(threat_data)}
    
    Suricata Documentation Context:
    {state['rag_context']}
    
    Identify any high-risk entities.
    """
    analysis = llm.invoke(prompt)  # No .content
    
    return {
        "threat_intel": {
            "raw": threat_data,
            "llm_analysis": analysis
        }
    }

def extract_content(response):
    """Normalize LLM output to string"""
    if isinstance(response, BaseMessage):
        return response.content
    elif isinstance(response, str):
        return response
    else:
        return str(response)

def anomaly_detection_node(state: AnalysisState) -> Dict:
    """Node 6: Anomaly detection"""
    print("⚠️ Detecting anomalies...")

    # Prepare data for LLM analysis
    analysis_data = {
        "suricata_events": state["suricata_events"][:5],  # Sample
        "protocol_analysis": extract_content(state["protocol_analysis"]["llm_analysis"]),
        "threat_intel": extract_content(state["threat_intel"]["llm_analysis"])
    }

    prompt = f"""
    Analyze this network data for security anomalies:
    {json.dumps(analysis_data)[:3000]}

    Suricata Documentation Context:
    {state['rag_context']}

    Identify potential threats and rate severity (1-10).
    """
    raw_analysis = llm.invoke(prompt)
    analysis = extract_content(raw_analysis)

    return {
        "anomalies": [{"description": analysis, "severity": 7}],  # Simplified
        "rag_context": retrieve_suricata_docs("Anomaly detection in network traffic")
    }
def visualization_node(state: AnalysisState) -> Dict:
    """Node 7: Attack visualization"""
    print("📊 Generating attack visualization...")
    
    # Prepare data for LLM
    analysis_data = {
        "anomalies": state["anomalies"],
        "key_events": state["suricata_events"][:3]
    }
    
    prompt = f"""
    Create a visualization plan for these network anomalies:
    {json.dumps(analysis_data)}
    
    Suggest:
    1. Attack chain visualization approach
    2. Key entities to include
    3. Recommended graph type
    """
    visualization_plan = llm.invoke(prompt)
    
    return {
        "visualization_data": {
            "plan": visualization_plan,
            "entities": ["src_ips", "dest_ips", "malicious_domains"]
        }
    }
def report_generation_node(state: AnalysisState) -> Dict:
    """Node 8: Generate final report"""
    print("📝 Generating comprehensive report...")
    
    # Safely extract content from all LLM results
    suricata_summary = json.dumps(state['suricata_events'][:3])[:1000]
    protocol_analysis = extract_content(state['protocol_analysis']['llm_analysis'])[:1000]
    threat_intel_analysis = extract_content(state['threat_intel']['llm_analysis'])[:1000]
    anomalies = json.dumps(state['anomalies'])[:2000]
    visualization_plan = extract_content(state['visualization_data']['plan'])[:2000]
    rag_context = extract_content(state['rag_context'])[:2000]

    prompt = f"""
    Create a comprehensive security report for PCAP analysis:

    Suricata Events Summary:
    {suricata_summary}

    Protocol Analysis:
    {protocol_analysis}

    Threat Intelligence:
    {threat_intel_analysis}

    Anomalies Detected:
    {anomalies}

    Visualization Plan:
    {visualization_plan}

    Suricata Documentation Context:
    {rag_context}

    Structure the report with:
    - Executive Summary
    - Technical Findings
    - Threat Assessment
    - Recommended Actions
    - Visualization Strategy
    """
    
    raw_report = llm.invoke(prompt)
    report = extract_content(raw_report)

    return {
        "report": report
    }
# ------------------------
# Build the LangGraph
# ------------------------

# Create the workflow
workflow = StateGraph(AnalysisState)


# Add nodes
workflow.add_node("init", initialize_analysis)
workflow.add_node("suricata", run_suricata_node)
workflow.add_node("zeek", run_zeek_node)
workflow.add_node("merge_results", lambda state: state)  # Simple merge node
workflow.add_node("protocols", protocol_analysis_node)
workflow.add_node("threat_intel_node", threat_intel_node)
workflow.add_node("anomalies_detection_node", anomaly_detection_node)
workflow.add_node("visualization", visualization_node)
workflow.add_node("report_generation_node", report_generation_node)

# Set up edges for parallel execution and merging
workflow.set_entry_point("init")
workflow.add_edge("init", "suricata")
workflow.add_edge("init", "zeek")
workflow.add_edge("suricata", "merge_results")
workflow.add_edge("zeek", "merge_results")
workflow.add_edge("merge_results", "protocols")
workflow.add_edge("protocols", "threat_intel_node")
workflow.add_edge("threat_intel_node", "anomalies_detection_node")
workflow.add_edge("anomalies_detection_node", "visualization")
workflow.add_edge("visualization", "report_generation_node")
workflow.add_edge("report_generation_node", END)

# Compile the graph
app = workflow.compile()

# ------------------------
# Execute the workflow
# ------------------------

def run_analysis(pcap_path: str):
    """Execute the analysis workflow"""
    inputs = {"pcap_path": pcap_path}
    results = app.invoke(inputs)
    
    print("\n" + "="*50)
    print("✅ ANALYSIS COMPLETE")
    print("="*50)
    
    # Save full report
    with open("pcap_analysis_report.md", "w") as f:
        f.write(results["report"])
    
    # Print summary
    print("\n📄 Report Summary:")
    print(results["report"][:2000] + "...")
    print(f"\nFull report saved to pcap_analysis_report.md")

# Run the analysis
if __name__ == "__main__":
    run_analysis(PCAP_FILE)
