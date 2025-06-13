from langgraph.graph import StateGraph, END
from typing import TypedDict

# Dummy state and node for example
class AnalysisState(TypedDict):
    pcap_path: str

def dummy_node(state: AnalysisState) -> dict:
    return {}

# Create the workflow
workflow = StateGraph(AnalysisState)
# Add nodes
workflow.add_node("init", dummy_node)
workflow.add_node("suricata", dummy_node)
workflow.add_node("zeek", dummy_node)
workflow.add_node("merge_results", lambda state: state)  # Simple merge node
workflow.add_node("protocols", dummy_node)
workflow.add_node("threat_intel_node", dummy_node)
workflow.add_node("anomalies_detection_node", dummy_node)
workflow.add_node("visualization", dummy_node)
workflow.add_node("report_generation_node", dummy_node)

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

# Draw and save the graph
try:
    png_data = app.get_graph().draw_mermaid_png()
    with open("workflow_graph.png", "wb") as f:
        f.write(png_data)
    print("✅ Graph saved as 'workflow_graph.png'")
except Exception as e:
    print("❌ Could not render graph:", str(e))