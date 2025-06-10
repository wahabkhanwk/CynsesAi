from langgraph.graph import StateGraph, END
from typing import TypedDict

# Dummy state and node for example
class AnalysisState(TypedDict):
    pcap_path: str

def dummy_node(state: AnalysisState) -> dict:
    return {}

# Create the workflow
workflow = StateGraph(AnalysisState)
workflow.add_node("init", dummy_node)
workflow.add_node("suricata", dummy_node)
workflow.add_node("zeek", dummy_node)
workflow.add_node("protocols", dummy_node)
workflow.add_node("threat_intel", dummy_node)
workflow.add_node("anomalies", dummy_node)
workflow.add_node("visualization", dummy_node)
workflow.add_node("report", dummy_node)

# Set up edges
workflow.set_entry_point("init")
workflow.add_edge("init", "suricata")
workflow.add_edge("suricata", "zeek")
workflow.add_edge("zeek", "protocols")
workflow.add_edge("protocols", "threat_intel")
workflow.add_edge("threat_intel", "anomalies")
workflow.add_edge("anomalies", "visualization")
workflow.add_edge("visualization", "report")
workflow.add_edge("report", END)

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