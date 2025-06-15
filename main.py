from modules.suricata_parser import run_suricata
from modules.zeek import run_zeek
from modules.threat_intel import real_threat_intel
from modules.protocol_analysis import analyze_protocols 
from modules.anomaly_detection import parse_fastlog , process_alerts
from modules.report_generation import generate_report
from modules.visualization import parse_suricata_fast_log, parse_zeek_conn_log, extract_packet_data_with_scapy, build_enhanced_attack_graph, generate_networkx_plot, generate_plotly_interactive
from modules.network_traffic_classifier import predictingRowsCategoryOnGPU, packets_brief
import os
import json
import subprocess
from typing import TypedDict, Annotated, Dict, List, Set, Any
from langgraph.graph import StateGraph, END
#from langchain_community.llms import Ollama
from langchain_openai import ChatOpenAI
from langchain_community.vectorstores import Chroma
#from langchain_community.embeddings import OllamaEmbeddings
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import WebBaseLoader
from langchain_ollama import OllamaLLM, OllamaEmbeddings
from pathlib import Path
#from suricata_parser import run_suricata
from langchain_core.messages import BaseMessage
import time
import asyncio
from diskcache import Cache
#import mermaid
from IPython.display import Image

# Import only necessary settings, paths will be dynamic
from config.settings import (
    PCAP_FILE, SURICATA_DOCS_URL , CHUTES_API_BASE , CHUTES_API_KEY,
    SURICATA_CONFIG, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY,
    THREAT_INTEL_FILENAME, ANOMALIES_FILENAME # Added new imports
)
import shutil
import logging
import uuid # For default analysis ID

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

os.environ["USER_AGENT"] = "CynsesAI-PCAP-Analyzer/1.0"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

# Initialize diskcache Cache

#cache = Cache("./cache_dir")

# Configuration
USE_OLLAMA = False  # Set to False for API-based LLM

# Define the analysis state
class AnalysisState(TypedDict):
    pcap_path: str
    analysis_id: str  # Added
    base_output_dir: str # Added
    suricata_events: List[Dict]
    zeek_logs: Dict
    protocol_analysis: Dict
    threat_intel: Dict
    anomalies: List[Dict]
    visualization_data: Dict
    report: str
    rag_context: str


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
        max_tokens=4096,
    )
    embeddings = None  

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

#@cache.memoize()
def retrieve_suricata_docs(query: str) -> str:
    """Retrieve relevant Suricata documentation"""
    docs = suricata_vectorstore.similarity_search(query, k=3)
    return "\n\n".join([d.page_content for d in docs])

# ------------------------
# LangGraph Node Functions
# ------------------------
def cleanup_resources(base_analysis_path: str = None, additional_paths: List[str] = None):
    """
    Clean up analysis resources. If base_analysis_path is provided,
    it cleans resources within that specific path. Otherwise, cleans common global paths.
    
    Args:
        base_analysis_path: The base directory for a specific analysis.
        additional_paths: List of additional global paths to clean up.
    """
    paths_to_clean = []
    if base_analysis_path:
        paths_to_clean.extend([
            os.path.join(base_analysis_path, "suricata_output"),
            os.path.join(base_analysis_path, "zeek_output"),
            os.path.join(base_analysis_path, "attack_graphs"),
            os.path.join(base_analysis_path, "temp_diagram.mmd"),
            os.path.join(base_analysis_path, "attack_flow.png"),
            os.path.join(base_analysis_path, "pcap_analysis_report.md")
        ])
    else:
        # Global paths (legacy or general cleanup)
        paths_to_clean.extend([
            "suricata_output", # Default legacy dir
            "zeek_output",     # Default legacy dir
            "attack_graphs",   # Default legacy dir
            "attack_graphs",   # Corrected from GRAPH_OUTPUT_DIR variable to string literal
            "temp_diagram.mmd",
            "attack_flow.png",
            "pcap_analysis_report.md"
        ])

    paths_to_clean.append("__pycache__") # General Python cache

    if additional_paths:
        paths_to_clean.extend(additional_paths)

    for path_str in paths_to_clean:
        path_obj = Path(path_str)
        try:
            path_obj = Path(path)
            if path_obj.exists():
                if path_obj.is_dir():
                    shutil.rmtree(path_obj)
                    logger.info(f"Successfully removed directory: {path_str}")
                else:
                    path_obj.unlink()
                    logger.info(f"Successfully removed file: {path_str}")
        except Exception as e:
            logger.error(f"Failed to remove {path_str}: {str(e)}")

def initialize_analysis(state: AnalysisState) -> Dict:
    """Node 1: Initialize analysis, setting up paths based on analysis_id."""
    analysis_id = state.get("analysis_id", str(uuid.uuid4()))
    base_output_dir = state.get("base_output_dir", os.path.join("analysis_results", analysis_id))

    os.makedirs(base_output_dir, exist_ok=True)
    # Optional: Clean up previous results for this specific analysis_id if desired
    # cleanup_resources(base_analysis_path=base_output_dir)

    print(f"🚀 Starting PCAP analysis workflow for analysis ID: {analysis_id}")
    print(f"Output will be stored in: {base_output_dir}")

    return {
        "pcap_path": state["pcap_path"],
        "analysis_id": analysis_id,
        "base_output_dir": base_output_dir,
        "rag_context": retrieve_suricata_docs("PCAP analysis with Suricata")
    }

def run_suricata_node(state: AnalysisState) -> Dict:
    """Node 2: Run Suricata analysis with dynamic output path."""
    print("🔍 Running Suricata on PCAP...")
    base_output_dir = state["base_output_dir"]
    # Ensure SURICATA_CONFIG is available, e.g. from config.settings
    events = run_suricata(state["pcap_path"], output_dir_base=base_output_dir)
    
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
    """Node 3: Run Zeek analysis with dynamic output path."""
    print("🕵️ Running Zeek on PCAP...")
    base_output_dir = state["base_output_dir"]
    return {"zeek_logs": run_zeek(state["pcap_path"], output_dir_base=base_output_dir)}

#def network_traffic_classification_node(state: AnalysisState) -> Dict:
    """Node: Classify network traffic using BERT model"""
    print("🤖 Running network traffic classifier...")
    # You can use the PCAP file from the state or config
    pcap_path = state.get("pcap_path", PCAP_FILE)
    # Call the classifier (you can adjust filter_payload and debug as needed)
    predictingRowsCategoryOnGPU(pcap_path, filter_payload=None, debug=False)
    # Optionally, you can collect results from packets_brief if you want to add to state
    # from modules.network_traffic_classifier import packets_brief
    # return {"traffic_classification": dict(packets_brief)}
    return {}  # If you don't need to update the state

def network_traffic_classification_node(state: AnalysisState) -> Dict:
    """Node: Classify network traffic using BERT model"""
    print("🤖 Running network traffic classifier...")
    
    pcap_path = state.get("pcap_path", PCAP_FILE)
    predictingRowsCategoryOnGPU(pcap_path, filter_payload=None, debug=False)

    # Extract results
    classification_data = dict(packets_brief) if 'packets_brief' in globals() else {}

    return {
        "traffic_classification": classification_data
    }
def ask_run_classifier() -> bool:
    """Prompt user whether to run the network traffic classifier node."""
    while True:
        ans = input("Do you want to run the network traffic classifier? (y/n): ").strip().lower()
        if ans in ("y", "yes"):
            return True
        elif ans in ("n", "no"):
            return False
        else:
            print("Please enter 'y' or 'n'.")



def generate_attack_diagram(state: AnalysisState) -> str:
    """Generate Mermaid diagram code based on detected attack patterns"""
    # Extract key entities from analysis
    internal_ips = set()
    external_ips = set()
    relationships = []
    
    # Process Suricata events
    for event in state.get('suricata_events', []):
        src_ip = event.get('src_ip')
        dest_ip = event.get('dest_ip')
        if src_ip and dest_ip:
            if src_ip.startswith('10.') or src_ip.startswith('192.168.'):
                internal_ips.add(src_ip)
                external_ips.add(dest_ip)
                relationships.append(f"{src_ip} -->|{event.get('event_type','Alert')}| {dest_ip}")
            elif dest_ip.startswith('10.') or dest_ip.startswith('192.168.'):
                internal_ips.add(dest_ip)
                external_ips.add(src_ip)
                relationships.append(f"{src_ip} -->|{event.get('event_type','Alert')}| {dest_ip}")
    
    # Process Zeek logs
    conn_log = state.get('zeek_logs', {}).get('conn.log', [])
    for line in conn_log[:50]:  # Sample first 50 connections
        parts = line.split('\t')
        if len(parts) > 5:
            src_ip, dest_ip = parts[2], parts[4]
            if src_ip and dest_ip:
                relationships.append(f"{src_ip} -->|Connection| {dest_ip}")
    
    # Build Mermaid diagram
    diagram = ["graph LR"]
    for ip in internal_ips:
        diagram.append(f"    I{ip.replace('.','_')}[Internal Host\\n{ip}]")
    for ip in external_ips:
        diagram.append(f"    E{ip.replace('.','_')}[External Server\\n{ip}]")
    for relation in set(relationships):  # Deduplicate
        diagram.append(f"    {relation}")
    
    return "\n".join(diagram)

def render_diagram(diagram_code: str, state: AnalysisState) -> str:
    """Render Mermaid diagram to image file using mermaid-cli, using base_output_dir from state."""
    try:
        base_output_dir = state["base_output_dir"]
        # Create a temporary file for the Mermaid code in the analysis specific output directory
        temp_mmd_file = Path(os.path.join(base_output_dir, "temp_diagram.mmd"))
        temp_mmd_file.write_text(diagram_code)

        # Output image path (dynamic, within base_output_dir)
        img_path = os.path.join(base_output_dir, "attack_flow.png")

        # Run mermaid-cli to generate the image
        subprocess.run([
            "mmdc",
            "-i", str(temp_mmd_file),
            "-o", img_path,
            "-t", "dark",
            "-w", "1200"
        ], check=True)

        # Remove the temporary Mermaid file
        temp_mmd_file.unlink()

        return img_path
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Diagram rendering failed: {e}")
        return ""
    except Exception as e:
        print(f"⚠️ Unexpected error during diagram rendering: {e}")
        return ""
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

    # Call the generic analyzer on all logs
    zeek_logs = state.get("zeek_logs", {})
    rag_context = state.get("rag_context", "")

    analysis_result = analyze_protocols(zeek_logs, rag_context)

    return {
        "protocol_analysis": analysis_result
    }
    
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

def threat_intel_node(state: Dict[str, Any]) -> Dict[str, Any]:
    """Node 5: Threat intelligence enrichment"""
    print("🌐 Enriching with threat intelligence...")

    # Step 1: Extract unique IPs from Suricata events
    ips: Set[str] = set()
    for event in state.get("suricata_events", []):
        if "src_ip" in event:
            ips.add(event["src_ip"])
        if "dest_ip" in event:
            ips.add(event["dest_ip"])

    if not ips:
        return {
            "threat_intel": {
                "raw": {},
                "llm_analysis": "No IPs found in Suricata events for threat intelligence lookup."
            }
        }

    # Step 2: Query threat intel for each unique IP using the cached function
    threat_data = {ip: real_threat_intel(ip) for ip in ips}

    # Step 3: Generate prompt for LLM analysis
    prompt = f"""
    Analyze this threat intelligence data:
    {json.dumps(threat_data, indent=2)}
    
    Suricata Documentation Context:
    {state.get('rag_context', 'No context provided')}
    
    Identify any high-risk entities, malicious behavior, or suspicious patterns.
    """
    
    # Step 4: Get LLM analysis
    try:
        analysis_response = llm.invoke(prompt)
        llm_analysis_content = extract_content(analysis_response)
    except Exception as e:
        llm_analysis_content = f"LLM analysis failed: {str(e)}"

    # Data to be returned and saved
    output_data = {
        "raw_threat_data": threat_data,
        "llm_analysis": llm_analysis_content
    }

    # Save to file
    base_output_dir = state.get("base_output_dir")
    if base_output_dir:
        file_path = os.path.join(base_output_dir, THREAT_INTEL_FILENAME)
        try:
            with open(file_path, "w") as f:
                json.dump(output_data, f, indent=4)
            print(f"Threat intelligence data saved to {file_path}")
        except Exception as e:
            print(f"Failed to save threat intelligence data: {e}")
    else:
        print("Warning: base_output_dir not found in state, cannot save threat intelligence.")

    # Step 5: Return enriched state (structure as expected by the rest of the graph)
    return {
        "threat_intel": { # This is the key the graph expects
            "raw": threat_data, # Keep original structure for compatibility if other nodes use this exact format
            "llm_analysis": llm_analysis_content
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
    """Node 6: Anomaly Detection Node with dynamic Suricata output path."""
    print("⚠️ Detecting anomalies...")
    base_output_dir = state["base_output_dir"]
    suricata_output_dir = os.path.join(base_output_dir, "suricata_output")

    try:
        # Step 1: Parse and filter logs from Suricata output directory
        parsed_logs = parse_fastlog(suricata_output_dir)

        # Step 2: Detect anomalies using filtered logs
        anomaly_result = asyncio.run(process_alerts(parsed_logs))

        # Step 3: Summarize results for reporting
        summary = summarize_anomalies(anomaly_result.get("anomalies", []))

        # Add summary to the anomaly_result to save it too
        anomaly_result_to_save = {
            "anomalies": anomaly_result.get("anomalies", []),
            "anomaly_summary": summary,
            "status": anomaly_result.get("status", "unknown") # ensure status is also saved
        }

        # Save anomaly_result_to_save to file
        base_output_dir = state.get("base_output_dir")
        if base_output_dir:
            file_path = os.path.join(base_output_dir, ANOMALIES_FILENAME)
            try:
                with open(file_path, "w") as f:
                    json.dump(anomaly_result_to_save, f, indent=4)
                print(f"Anomaly detection data saved to {file_path}")
            except Exception as e:
                print(f"Failed to save anomaly detection data: {e}")
        else:
            print("Warning: base_output_dir not found in state, cannot save anomaly data.")

        # Step 4: Update state with results (ensure this matches what subsequent nodes expect)
        return {
            "anomalies": anomaly_result.get("anomalies", []), # Original list of anomalies
            "anomaly_summary": summary, # The generated summary
            "status": "completed" # Overall status of this node
        }

    except Exception as e:
        print(f"❌ Anomaly detection failed: {e}")
        # Save error information if possible
        base_output_dir = state.get("base_output_dir")
        if base_output_dir:
            error_output = {
                "anomalies": [],
                "anomaly_summary": f"⚠️ Anomaly detection failed: {e}",
                "status": "failed"
            }
            file_path = os.path.join(base_output_dir, ANOMALIES_FILENAME)
            try:
                with open(file_path, "w") as f:
                    json.dump(error_output, f, indent=4)
                print(f"Anomaly detection error data saved to {file_path}")
            except Exception as save_e:
                print(f"Failed to save anomaly detection error data: {save_e}")

        return { # Return structure consistent with success case
            "anomalies": [],
            "anomaly_summary": f"⚠️ Anomaly detection failed: {e}",
            "status": "failed"
        }
        
def visualization_node(state: AnalysisState) -> Dict:
    """Node 7: Attack visualization with threat classification"""
    print("📊 Generating attack visualization...")

    # Paths to intermediate files
    pcap_path = state.get("pcap_path", PCAP_FILE)
    base_output_dir = state["base_output_dir"]
    suricata_log_path = os.path.join(base_output_dir, "suricata_output", "fast.log")
    zeek_log_path = os.path.join(base_output_dir, "zeek_output", "conn.log")

    # Extract data
    alerts = parse_suricata_fast_log(suricata_log_path)
    connections = parse_zeek_conn_log(zeek_log_path)
    packets = extract_packet_data_with_scapy(pcap_path)

    # Build graph
    G = build_enhanced_attack_graph(alerts, connections, packets)

    # Save visualizations to dynamic path
    graph_output_dir = os.path.join(base_output_dir, "attack_graphs")
    os.makedirs(graph_output_dir, exist_ok=True)

    static_path = os.path.join(graph_output_dir, "attack_graph.png")
    interactive_path = os.path.join(graph_output_dir, "interactive_attack_graph.html")

    generate_networkx_plot(G, static_path)
    generate_plotly_interactive(G, interactive_path)

    # Return results
    return {
        "visualization_data": {
            "graph": G,
            "graph_image": static_path, # Path is now absolute or relative to repo root
            "graph_html": interactive_path, # Path is now absolute or relative to repo root
            "plan": f"""
            ### Attack Graph Summary
            - Total nodes: {len(G.nodes())}
            - Total edges: {len(G.edges())}
            - Visualizations saved to:
              - Static: `{static_path}`
              - Interactive: `{interactive_path}`
            """
        }
    }
def summarize_suricata_events(events):
    """Summarize Suricata events for the report."""
    if not events:
        return "No significant Suricata events detected."
    try:
        return "\n".join(
            f"- [{e.get('timestamp', '')}] {e.get('event_type', '')}: {e.get('alert', {}).get('signature', str(e)[:100])}"
            for e in events
        )
    except Exception:
        return str(events)[:3000]

def summarize_anomalies(anomalies: list):
    """
    Summarize anomalies for final report output.
    """
    if not anomalies:
        return "✅ No anomalies detected."

    try:
        return "\n".join(
            f"- Severity {a.get('severity', '?')}: {a.get('description', 'Unknown issue')}"
            for a in anomalies
        )
    except Exception:
        return "⚠️ Failed to summarize anomalies due to formatting issues.\n" + str(anomalies)[:2000]
    

def report_generation_node(state: AnalysisState) -> Dict:
    """Node 8: Generate final report with attack diagrams"""
    print("📝 Generating comprehensive report with attack diagrams...")
    
    base_output_dir = state["base_output_dir"]
    
    # Generate attack diagram
    diagram_code = generate_attack_diagram(state) # Assumes generate_attack_diagram uses state for paths if needed
    diagram_path = render_diagram(diagram_code, state) if diagram_code else "" # Pass state to render_diagram

    # Safely summarize inputs
    suricata_events = state.get('suricata_events') or []
    protocol_analysis_dict = state.get('protocol_analysis') or {}
    threat_intel_dict = state.get('threat_intel') or {}
    anomalies_list = state.get('anomalies') or []
    visualization_data = state.get('visualization_data') or {}
    rag_context_val = state.get('rag_context') or ""
    
    # Generate summaries
    suricata_summary = summarize_suricata_events(suricata_events[:3000])
    protocol_analysis = extract_content(protocol_analysis_dict.get('llm_analysis', ''))[:1000]
    threat_intel_analysis = extract_content(threat_intel_dict.get('llm_analysis', ''))[:1000]
    anomalies = summarize_anomalies(anomalies_list)
    visualization_plan = extract_content(visualization_data.get('plan', ''))[:2000]
    rag_context = extract_content(rag_context_val)[:2000]
    traffic_classification = (
        json.dumps(state.get('traffic_classification', {}), indent=2)[:2000] 
        if state.get('traffic_classification') 
        else "No traffic classification data available."
    )
    graph_image = visualization_data.get('graph_image', None)
    
    # Build markdown image references (relative to the report in base_output_dir)
    image_sections = []
    if diagram_path and os.path.exists(diagram_path):
        # diagram_path is now like "analysis_results/uuid/attack_flow.png"
        # The report will be in "analysis_results/uuid/report.md"
        # So, relative path is just the filename.
        image_sections.append(f"\n\n![Attack Flow Diagram](./{os.path.basename(diagram_path)})\n")
    if graph_image and os.path.exists(graph_image):
        # graph_image is like "analysis_results/uuid/attack_graphs/graph.png"
        image_sections.append(f"\n\n![Network Attack Graph](./attack_graphs/{os.path.basename(graph_image)})\n")
        
    # Prepare diagram code for report
    diagram_section = ""
    if diagram_code:
        diagram_section = (
            "\n\n### Attack Flow Diagram\n"
            "```mermaid\n"
            f"{diagram_code}\n"
            "```\n"
        )
    
    prompt = f"""
    Create a comprehensive security report for PCAP analysis:
    Visualization Summary:
    {visualization_plan}{''.join(image_sections)}
    
    {diagram_section}
    
    Suricata Events Summary:
    {suricata_summary}
    
    Protocol Analysis:
    {protocol_analysis}
    
    Traffic Classification Summary:
    {traffic_classification}
    
    Threat Intelligence:
    {threat_intel_analysis}
    
    Anomalies Detected:
    {anomalies}
    
    Structure the report with these sections:
    1. Executive Summary
    2. Technical Findings
      - Include the Mermaid diagram code block
    3. Attack Flow Analysis
    4. Threat Assessment
    5. Recommended Actions
    6. Mitre ATT&CK Mapping
    7. Threat Classification
    
    Include Suricata rules to prevent similar attacks
    """
        # Implement retry logic with exponential backoff
    max_retries = 3
    retry_delay = 5  # seconds
    report = "⚠️ Error: Full report could not be generated."
    
    for attempt in range(max_retries):
        try:
            raw_report = llm.invoke(prompt)
            report = extract_content(raw_report)
            break  # Success - exit retry loop
        except Exception as e:
            print(f"[Attempt {attempt + 1}/{max_retries}] Report generation failed: {str(e)[:200]}")
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                # On final failure, generate a minimal report
                report = f"""
                ⚠️ Partial Report (LLM service unavailable)
                
                # Network Security Analysis Summary
                
                ## Key Findings
                - Suricata Events: {len(suricata_events)} alerts
                - Anomalies Detected: {len(anomalies_list)}
                - Threat Indicators: {len(threat_intel_dict.get('matches', []))}
                
                ## Visualization
                {''.join(image_sections)}
                
                ## Next Steps
                Please retry later for full analysis details or contact support.
                """
    
    return {
        "report": report,
        "status": "complete" if not report.startswith("⚠️") else "partial",
        "diagram_code": diagram_code,
        "diagram_image": diagram_path
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
workflow.add_node("merge_results", lambda state: state)
workflow.add_node("protocols", protocol_analysis_node)
workflow.add_node("threat_intel_node", threat_intel_node)
workflow.add_node("anomalies_detection_node", anomaly_detection_node)
workflow.add_node("visualization", visualization_node)
workflow.add_node("report_generation_node", report_generation_node)
workflow.add_node("network_traffic_classifier", network_traffic_classification_node)

# Set up edges for parallel execution and merging
workflow.set_entry_point("init")
workflow.add_edge("init", "suricata")
workflow.add_edge("init", "zeek")
workflow.add_edge("suricata", "merge_results")
workflow.add_edge("zeek", "merge_results")

# Ask user if they want to run the classifier
RUN_CLASSIFIER = ask_run_classifier()

if RUN_CLASSIFIER:
    workflow.add_edge("merge_results", "network_traffic_classifier")
    workflow.add_edge("network_traffic_classifier", "protocols")
else:
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

# New main analysis function
def perform_pcap_analysis(pcap_file_path: str, analysis_id: str):
    """
    Performs the full PCAP analysis workflow for a given PCAP file and analysis ID.
    Saves outputs to a unique directory under analysis_results.
    Returns the path to the final report.
    """
    base_output_dir = os.path.join("analysis_results", analysis_id)
    os.makedirs(base_output_dir, exist_ok=True)

    # Initial state for the graph
    initial_state = {
        "pcap_path": pcap_file_path,
        "analysis_id": analysis_id,
        "base_output_dir": base_output_dir,
        # Initialize other fields to prevent potential KeyErrors if not set by init node
        "suricata_events": [],
        "zeek_logs": {},
        "protocol_analysis": {},
        "threat_intel": {},
        "anomalies": [],
        "visualization_data": {},
        "report": "",
        "rag_context": ""
    }

    # Clean up previous run for this ID, if any (optional, based on desired behavior)
    # cleanup_resources(base_analysis_path=base_output_dir)

    print(f"Starting analysis for {pcap_file_path} (ID: {analysis_id})...")
    results = app.invoke(initial_state)

    print("\n" + "="*50)
    print(f"✅ ANALYSIS COMPLETE for ID: {analysis_id}")
    print("="*50)

    # Save full report to the analysis-specific directory
    report_filename = "pcap_analysis_report.md"
    report_path = os.path.join(base_output_dir, report_filename)
    with open(report_path, "w") as f:
        f.write(results["report"])

    print("\n📄 Report Summary:")
    print(results["report"][:2000] + "...") # Display a snippet
    print(f"\nFull report saved to {report_path}")

    # Save other artifacts like diagram image path if needed, or ensure they are in results
    if "diagram_image" in results and results["diagram_image"]:
        print(f"Attack flow diagram saved to: {results['diagram_image']}")
    if "visualization_data" in results and results["visualization_data"].get("graph_image"):
        print(f"Network attack graph saved to: {results['visualization_data']['graph_image']}")

    return report_path, results # Return path and full results

def run_analysis_legacy(pcap_path: str):
    """Execute the analysis workflow (legacy, for comparison or testing specific parts without full ID structure)"""
    # This is closer to the original run_analysis, might not use analysis_id structure fully
    # For testing, ensure it sets up some default base_output_dir if nodes expect it.
    analysis_id = str(uuid.uuid4())
    base_output_dir = os.path.join("analysis_results", "legacy_run", analysis_id)
    os.makedirs(base_output_dir, exist_ok=True)

    inputs = {
        "pcap_path": pcap_path,
        "analysis_id": analysis_id,
        "base_output_dir": base_output_dir
    }
    results = app.invoke(inputs)
    
    print("\n" + "="*50)
    print("✅ LEGACY ANALYSIS COMPLETE")
    print("="*50)
    
    report_path = os.path.join(base_output_dir, "pcap_analysis_report.md")
    with open(report_path, "w") as f:
        f.write(results["report"])
    
    print("\n📄 Report Summary:")
    print(results["report"][:2000] + "...")
    print(f"\nFull report saved to {report_path}")
    return results


def summarize_state_for_gpt(state: AnalysisState) -> str:
    """
    Extract and summarize key info from the analysis state to provide context.
    Includes all nodes from the analysis graph.
    """
    if not isinstance(state, dict):
        return "⚠️ No analysis state available."

    summary = []

    # Suricata Events
    summary.append("## Suricata Alerts\n")
    summary.append(summarize_suricata_events(state.get("suricata_events", []))[:2000])

    # Zeek Logs
    summary.append("\n## Zeek Logs\n")
    zeek_logs = state.get("zeek_logs", {})
    if zeek_logs:
        for log_name, lines in zeek_logs.items():
            summary.append(f"### {log_name}\n")
            summary.append("\n".join(lines[:5])[:1000])
    else:
        summary.append("No Zeek logs available.")

    # Protocol Analysis
    summary.append("\n## Protocol Analysis\n")
    protocol_analysis = state.get("protocol_analysis", {})
    if protocol_analysis:
        llm_analysis = protocol_analysis.get("llm_analysis", "")
        summary.append(f"LLM Analysis: {extract_content(llm_analysis)[:1000]}")
        summary.append(f"\nRaw: {json.dumps(protocol_analysis.get('raw', {}), indent=2)[:1000]}")
    else:
        summary.append("No protocol analysis available.")

    # Threat Intelligence
    summary.append("\n## Threat Intelligence\n")
    threat_intel = state.get("threat_intel", {})
    if threat_intel:
        llm_analysis = threat_intel.get("llm_analysis", "")
        summary.append(f"LLM Analysis: {extract_content(llm_analysis)[:1000]}")
        summary.append(f"\nRaw: {json.dumps(threat_intel.get('raw', {}), indent=2)[:1000]}")
    else:
        summary.append("No threat intelligence available.")

    # Anomalies
    summary.append("\n## Anomalies\n")
    anomalies = state.get("anomalies", [])
    summary.append(summarize_anomalies(anomalies)[:2000])

    # Visualization
    summary.append("\n## Visualization\n")
    visualization = state.get("visualization_data", {})
    if visualization:
        summary.append(visualization.get("plan", "")[:1000])
        summary.append(f"Graph Image: {visualization.get('graph_image', 'N/A')}")
        summary.append(f"Graph HTML: {visualization.get('graph_html', 'N/A')}")
    else:
        summary.append("No visualization data available.")

    # Traffic Classification
    summary.append("\n## Traffic Classification\n")
    traffic_classification = state.get("traffic_classification", {})
    if traffic_classification:
        summary.append(json.dumps(traffic_classification, indent=2)[:1000])
    else:
        summary.append("No traffic classification data available.")

    # Report
    summary.append("\n## Report Summary\n")
    summary.append(str(state.get("report", ""))[:2000])

    # RAG Context
    summary.append("\n## RAG Context\n")
    summary.append(str(state.get("rag_context", ""))[:1000])

    return "\n".join(summary)
def build_prompt(history: list, context: str, user_input: str) -> str:
    """
    Build a prompt string combining conversation history, context, and current user input.
    """
    prompt = context + "\n\n"
    for turn in history:
        prompt += f"User: {turn['user']}\nAssistant: {turn['assistant']}\n"
    prompt += f"User: {user_input}\nAssistant:"
    return prompt

def interactive_gpt_session(final_state: AnalysisState):
    """
    Allow user to interact with GPT about the analysis results.
    """
    conversation_history = []
    print("You can now ask questions about the analysis. Type 'exit' to quit.")
    
    while True:
        user_input = input("Your question: ")
        if user_input.lower() in ("exit", "quit"):
            print("Exiting interactive session.")
            break
        
        # Prepare context from final_state (summarize or serialize relevant parts)
        context = summarize_state_for_gpt(final_state)
        
        # Combine conversation history + context + user input
        prompt = build_prompt(conversation_history, context, user_input)
        
        # Query the LLM (use the same llm instance as in your workflow)
        try:
            response = llm.invoke(prompt)
            if hasattr(response, "content"):
                response_text = response.content
            else:
                response_text = str(response)
        except Exception as e:
            response_text = f"Error from LLM: {e}"
        
        # Print and save response
        print("GPT:", response_text)
        conversation_history.append({"user": user_input, "assistant": response_text})

# Run the analysis
if __name__ == "__main__":
    # Example of using the new function
    sample_pcap_file = PCAP_FILE # Use the one from settings or provide a direct path
    analysis_session_id = f"cli_run_{str(uuid.uuid4())[:8]}" # Create a unique ID for this run

    print(f"Running analysis for PCAP: {sample_pcap_file} with ID: {analysis_session_id}")

    # Ensure the PCAP file exists
    if not os.path.exists(sample_pcap_file):
        print(f"Error: PCAP file not found at {sample_pcap_file}")
        print("Please ensure PCAP_FILE in config/settings.py points to a valid file or provide a direct path.")
    else:
        # Perform the analysis
        final_report_path, final_state = perform_pcap_analysis(sample_pcap_file, analysis_session_id)

        # Start interactive session with the results of the new analysis function
        # The final_state from perform_pcap_analysis should be compatible
        if final_state:
             interactive_gpt_session(final_state)
        else:
            print("Analysis did not return a final state for interactive session.")

    # To test the legacy run (optional):
    # print("\n\nRunning legacy analysis for comparison...")
    # legacy_final_state = run_analysis_legacy(PCAP_FILE)
    # if legacy_final_state:
    #     interactive_gpt_session(legacy_final_state) # If you want to test this too
