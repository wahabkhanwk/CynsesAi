import os
import json
import networkx as nx
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from pathlib import Path
from scapy.all import rdpcap, IP
from typing import List, Dict, Any
import requests
import numpy as np
import pandas as pd
from plotly.subplots import make_subplots
import ipaddress
from config.settings import ABUSEIPDB_API_KEY , PCAP_FILE , SURICATA_FAST_LOG , ZEEK_CONN_LOG  , GRAPH_OUTPUT_DIR # Ensure this is set in your settings
# --------------------------
# Configuration
# --------------------------
#PCAP_PATH = "/Users/macbook/Desktop/CynsesAI/sample.pcap"
#SURICATA_FAST_LOG = "/Users/macbook/Desktop/CynsesAI/suricata_output/fast.log"
#ZEEK_CONN_LOG = "/Users/macbook/Desktop/CynsesAI/zeek_output/conn.log"
#OUTPUT_DIR = "attack_graphs"
#THREAT_API_KEY = "99b0c8552352c73ac74739cf496a06d8e006ff2353d6b21d5d9a6e07f616f3d9dcc507b1eade1cca"

os.makedirs(GRAPH_OUTPUT_DIR, exist_ok=True)

# --------------------------
# Enhanced Helper Functions
# --------------------------

def parse_suricata_fast_log(path: str) -> List[Dict]:
    """Parse Suricata fast.log as plain text, not JSON."""
    alerts = []
    if not os.path.exists(path):
        print(f"[!] Suricata fast.log not found at {path}")
        return alerts

    with open(path) as f:
        for idx, line in enumerate(f):
            try:
                # Example fast.log line:
                # 06/10/2025-12:34:56.789012  [**] [1:2010935:2] ET MALWARE Possible Malware Traffic [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 192.168.1.100:12345 -> 93.184.216.34:80
                parts = line.strip().split()
                if len(parts) < 10:
                    continue
                timestamp = parts[0]
                src_ip = parts[-3].split(':')[0]
                dest_ip = parts[-1].split(':')[0]
                alert_desc = " ".join(parts[4:-6])
                alerts.append({
                    "id": idx,  # <-- add this line
                    "src": src_ip,
                    "dst": dest_ip,
                    "desc": alert_desc,
                    "timestamp": timestamp,
                    "severity": 3,  # Default, or parse from line if available
                    "category": "Uncategorized"
                })
            except Exception as e:
                print(f"Error parsing Suricata fast.log line: {e}")
    return alerts

def parse_zeek_conn_log(path: str) -> List[Dict]:
    """Parse Zeek conn.log with additional features"""
    connections = []
    if not os.path.exists(path):
        print(f"[!] Zeek conn.log not found at {path}")
        return connections

    try:
        # Use pandas for robust parsing
        df = pd.read_csv(path, delimiter='\t', comment='#', low_memory=False)
        if df.empty:
            return connections
            
        for _, row in df.iterrows():
            try:
                src = row.get('id.orig_h', '')
                dst = row.get('id.resp_h', '')
                
                # Validate IP addresses
                try:
                    ipaddress.ip_address(src)
                    ipaddress.ip_address(dst)
                except ValueError:
                    continue

                orig_bytes = row.get('orig_bytes', 0)
                resp_bytes = row.get('resp_bytes', 0)
                try:
                    orig_bytes = int(orig_bytes) if pd.notnull(orig_bytes) else 0
                    resp_bytes = int(resp_bytes) if pd.notnull(resp_bytes) else 0
                except Exception:
                    orig_bytes = 0
                    resp_bytes = 0

                connections.append({
                    "src": src,
                    "dst": dst,
                    "proto": row.get('proto', ''),
                    "service": row.get('service', ''),
                    "duration": row.get('duration', 0),
                    "bytes": orig_bytes + resp_bytes,
                    "conn_state": row.get('conn_state', '')
                })
            except Exception as e:
                print(f"Error processing Zeek row: {e}")
    except Exception as e:
        print(f"Failed to parse Zeek log: {e}")
        
    return connections

def extract_packet_data_with_scapy(pcap_path: str) -> List[Dict]:
    """Enhanced packet extraction with protocol detection"""
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        return []
    
    flows = []
    for pkt in packets:
        if IP in pkt:
            try:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                
                # Protocol mapping
                protocol_map = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP"
                }
                protocol = protocol_map.get(proto, f"Proto-{proto}")
                
                flows.append({
                    "src": src, 
                    "dst": dst, 
                    "proto": protocol,
                    "size": len(pkt)
                })
            except Exception as e:
                print(f"Error processing packet: {e}")
    return flows

def get_threat_score(ip: str) -> int:
    """Enhanced threat intelligence with caching and real data only"""
    # Private IP check
    try:
        if ipaddress.ip_address(ip).is_private:
            return 0
    except Exception:
        return 0  # Not a valid IP

    # Real API call
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            score = int(response.json()['data']['abuseConfidenceScore'])
            return min(score // 20, 5)
    except Exception as e:
        print(f"Threat lookup failed for {ip}: {str(e)}")

    return 0

# --------------------------
# Graph Building & Visualization
# --------------------------

def build_enhanced_attack_graph(alerts, connections, packets=None):
    """Create enriched attack graph with threat intel"""
    G = nx.DiGraph()
    threat_cache = {}
    
    def get_cached_threat(ip):
        if ip not in threat_cache:
            threat_cache[ip] = get_threat_score(ip)
        return threat_cache[ip]
    
    # Add nodes with threat scores
    all_ips = set()
    for data in [alerts, connections, packets or []]:
        for item in data:
            all_ips.add(item['src'])
            all_ips.add(item['dst'])
    
    for ip in all_ips:
        threat_score = get_cached_threat(ip)
        G.add_node(ip, 
                  threat_score=threat_score,
                  size=10 + threat_score * 5,
                  color_threat=threat_score,
                  label=f"{ip}\nThreat: {threat_score}/5")
    
    # Add Suricata alerts
    for alert in alerts:
        threat_weight = max(G.nodes[alert['src']]['threat_score'], 
                           G.nodes[alert['dst']]['threat_score'])
        edge_color = [
            "#4CAF50",  # Green
            "#FFC107",  # Amber
            "#FF9800",  # Orange
            "#F44336",  # Red
            "#B71C1C"   # Dark Red
        ][min(4, alert['severity'] - 1)]
        
        G.add_edge(
            alert["src"], alert["dst"],
            label=f"ALERT: {alert['desc'][:25]}",
            alert_id=alert.get('id', ''),  # <-- use .get() for safety
            alert_desc=alert['desc'],
            severity=alert['severity'],
            category=alert['category'],
            timestamp=alert['timestamp'],
            color=edge_color,
            width=alert['severity'] * 0.8,
            type="alert"
        )
    
    # Add Zeek connections
    for conn in connections:
        G.add_edge(
            conn["src"], conn["dst"],
            label=f"{conn['proto']} → {conn.get('service', '')}",
            bytes=conn.get('bytes', 0),
            duration=conn.get('duration', 0),
            conn_state=conn.get('conn_state', ''),
            color="#2196F3",  # Blue
            width=1 + min(conn.get('bytes', 0) / 5000, 5),
            type="connection"
        )
    
    # Add packet flows
    if packets:
        for flow in packets:
            G.add_edge(
                flow["src"], flow["dst"],
                label=f"PKT: {flow['proto']}",
                size=flow.get('size', 0),
                color="#9C27B0",  # Purple
                width=1 + min(flow.get('size', 0) / 1000, 5),
                type="packet"
            )
    
    return G

def generate_networkx_plot(G, filename="attack_graph.png"):
    """Create professional static visualization"""
    fig, ax = plt.subplots(figsize=(16, 12))  # Use explicit axes
    
    pos = nx.spring_layout(G, k=0.5, iterations=50, weight='width')
    node_sizes = [G.nodes[n].get('size', 15) for n in G.nodes()]
    node_colors = [G.nodes[n].get('color_threat', 0) for n in G.nodes()]
    edge_colors = [G[u][v].get('color', 'gray') for u, v in G.edges()]
    edge_widths = [G[u][v].get('width', 1) for u, v in G.edges()]

    nodes = nx.draw_networkx_nodes(
        G, pos, 
        node_size=node_sizes,
        node_color=node_colors,
        cmap=plt.cm.Reds,
        alpha=0.9,
        vmin=0,
        vmax=5,
        ax=ax
    )
    nx.draw_networkx_edges(
        G, pos, 
        edge_color=edge_colors,
        width=edge_widths,
        alpha=0.7,
        arrows=True,
        arrowstyle='->',
        arrowsize=15,
        ax=ax
    )
    node_labels = {n: f"{n}\nThreat: {G.nodes[n].get('threat_score', 0)}" for n in G.nodes()}
    nx.draw_networkx_labels(G, pos, node_labels, font_size=8, font_family="sans-serif", ax=ax)
    edge_labels = {}
    for u, v, d in G.edges(data=True):
        if d.get('type') == "alert":
            edge_labels[(u, v)] = d.get('label', '')
    nx.draw_networkx_edge_labels(
        G, pos, 
        edge_labels=edge_labels,
        font_color='red',
        font_size=8,
        alpha=0.9,
        ax=ax
    )
    plt.title("Enterprise Attack Graph with Threat Intelligence", fontsize=16)
    sm = plt.cm.ScalarMappable(cmap=plt.cm.Reds, norm=plt.Normalize(0, 5))
    sm.set_array([])
    fig.colorbar(sm, ax=ax, label='Threat Score')
    plt.figtext(0.5, 0.01, 
               "Node Color: Threat Level | Node Size: Threat Level\n"
               "Red Edges: Security Alerts | Blue Edges: Network Connections | Purple Edges: Packet Flows",
               ha="center", fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPH_OUTPUT_DIR, filename), dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[+] NetworkX attack graph saved to {filename}")

def generate_plotly_interactive(G, filename="interactive_attack_graph.html"):
    """Create advanced interactive visualization"""
    # Get node positions using spring layout
    pos = nx.spring_layout(G, k=0.6, weight='width', seed=42)
    
    # Create edge traces
    edge_traces = []
    edge_types = set(nx.get_edge_attributes(G, 'type').values())
    edge_colors = {
        "alert": "rgba(244, 67, 54, 0.7)",     # Red
        "connection": "rgba(33, 150, 243, 0.5)", # Blue
        "packet": "rgba(156, 39, 176, 0.5)"      # Purple
    }
    
    for edge_type in edge_types:
        edge_x = []
        edge_y = []
        hover_info = []
        
        for u, v, data in G.edges(data=True):
            if data.get('type') == edge_type:
                x0, y0 = pos[u]
                x1, y1 = pos[v]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
                
                # Custom hover text based on edge type
                if edge_type == "alert":
                    hover_text = (f"<b>ALERT</b><br>"
                                 f"Source: {u}<br>"
                                 f"Destination: {v}<br>"
                                 f"Severity: {data.get('severity', 'N/A')}<br>"
                                 f"Description: {data.get('alert_desc', '')}<br>"
                                 f"Category: {data.get('category', '')}")
                elif edge_type == "connection":
                    hover_text = (f"<b>CONNECTION</b><br>"
                                 f"Source: {u}<br>"
                                 f"Destination: {v}<br>"
                                 f"Protocol: {data.get('label', '')}<br>"
                                 f"Duration: {data.get('duration', 0):.2f}s<br>"
                                 f"Bytes: {data.get('bytes', 0)}")
                else:  # packet
                    hover_text = (f"<b>PACKET</b><br>"
                                 f"Source: {u}<br>"
                                 f"Destination: {v}<br>"
                                 f"Protocol: {data.get('proto', '')}<br>"
                                 f"Size: {data.get('size', 0)} bytes")
                
                hover_info.append(hover_text)
                hover_info.append(hover_text)  # For both segments
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.5, color=edge_colors.get(edge_type, "gray")),
            hoverinfo='text',
            hovertext=hover_info,
            mode='lines',
            name=f"{edge_type.capitalize()}s",
            legendgroup=edge_type
        )
        edge_traces.append(edge_trace)
    
    # Create node trace
    node_x = []
    node_y = []
    node_text = []
    node_size = []
    node_color = []
    node_hover = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        threat_score = G.nodes[node].get('threat_score', 0)
        node_size.append(15 + threat_score * 8)
        node_color.append(threat_score)
        node_text.append(node)
        
        # Node hover info
        node_hover.append(
            f"<b>Node: {node}</b><br>"
            f"Threat Score: {threat_score}/5<br>"
            f"Alerts: {sum(1 for edge in G.in_edges(node) if G.edges[edge].get('type') == 'alert')}"
        )
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=node_text,
        textposition="top center",
        hovertext=node_hover,
        hoverinfo='text',
        marker=dict(
            showscale=True,
            colorscale='Reds',
            size=node_size,
            color=node_color,
        colorbar=dict(
            thickness=15,
            title=dict(text='Threat Score', font=dict(size=12)),  # Fixed here
            xanchor='left'
        ),
        line=dict(width=2, color='DarkSlateGrey')
    ),
        name="Hosts",
        textfont=dict(size=10)
    )
    
    # Create figure
    fig = go.Figure(
        data=edge_traces + [node_trace],
        layout=go.Layout(
            title='<b>Interactive Enterprise Attack Graph</b>',
            font=dict(size=20),
            showlegend=True,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=50),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            ),
            height=800
        )
    )
    
    # Add annotations
    fig.add_annotation(
        x=0.5,
        y=-0.1,
        xref="paper",
        yref="paper",
        text="Node Size: Threat Level | Node Color: Threat Level | Red Lines: Security Alerts | Blue Lines: Connections",
        showarrow=False,
        font=dict(size=12)
    )
    
    fig.write_html(os.path.join(GRAPH_OUTPUT_DIR, filename))
    print(f"[+] Interactive Plotly graph saved to {filename}")

def generate_summary_report(alerts, connections, packets, filename="attack_summary.html"):
    """Generate comprehensive HTML report"""
    # Threat distribution
    threat_counts = {}
    for ip in set([a['src'] for a in alerts] + [a['dst'] for a in alerts]):
        threat_counts[ip] = get_threat_score(ip)
    
    high_threat_ips = [ip for ip, score in threat_counts.items() if score >= 4]
    
    # Alert analysis
    alert_severities = [a['severity'] for a in alerts]
    alert_categories = {}
    for a in alerts:
        alert_categories[a['category']] = alert_categories.get(a['category'], 0) + 1
    
    # Connection analysis
    connection_bytes = [c.get('bytes', 0) for c in connections]
    # Create figures
    fig = make_subplots(
        rows=2, 
        cols=2,
        specs=[[{"type": "pie"}, {"type": "bar"}],
               [{"type": "histogram"}, {"type": "scatter"}]],
        subplot_titles=(
            "Alert Severity Distribution",
            "Top Alert Categories",
            "Connection Size Distribution",
            "Threat Score vs Alert Count"
        )
    )
    
    # Severity pie chart
    sev_counts = {sev: alert_severities.count(sev) for sev in set(alert_severities)}
    fig.add_trace(
        go.Pie(
            labels=[f"Severity {k}" for k in sev_counts.keys()],
            values=list(sev_counts.values())
        ),
        row=1, col=1
    )
    
    # Alert categories bar chart
    fig.add_trace(
        go.Bar(
            x=list(alert_categories.keys()),
            y=list(alert_categories.values())),
        row=1, col=2
    )
    
    # Connection size histogram
    if connection_bytes:
        fig.add_trace(
            go.Histogram(
                x=connection_bytes,
                nbinsx=20,
                marker_color='#2196F3'),
            row=2, col=1
        )
    
    # Threat vs Alerts scatter
    ip_alert_counts = {}
    for ip in threat_counts:
        ip_alert_counts[ip] = sum(1 for a in alerts if a['src'] == ip or a['dst'] == ip)
    
    fig.add_trace(
        go.Scatter(
            x=list(threat_counts.values()),
            y=list(ip_alert_counts.values()),
            mode='markers',
            text=list(ip_alert_counts.keys()),
            marker=dict(
                size=10,
                color=list(threat_counts.values()),
                colorscale='Reds',
                showscale=True
            )),
        row=2, col=2
    )
    
    fig.update_layout(
        height=800,
        title_text="Attack Analysis Summary",
        showlegend=False
    )
    
    # Save report
    fig.write_html(os.path.join(GRAPH_OUTPUT_DIR, filename))
    print(f"[+] Summary report saved to {filename}")

# --------------------------
# Main Execution
# --------------------------

if __name__ == "__main__":
    print("[+] Parsing security data...")
    suricata_alerts = parse_suricata_fast_log(SURICATA_FAST_LOG)
    zeek_connections = parse_zeek_conn_log(ZEEK_CONN_LOG)
    packet_flows = extract_packet_data_with_scapy(PCAP_FILE)
    
    print(f"[+] Loaded: {len(suricata_alerts)} alerts, {len(zeek_connections)} connections, {len(packet_flows)} packets")
    
    print("[+] Building attack graph...")
    attack_graph = build_enhanced_attack_graph(
        suricata_alerts, 
        zeek_connections, 
        packet_flows
    )
    
    print("[+] Generating visualizations...")
    generate_networkx_plot(attack_graph, "enterprise_attack_graph.png")
    generate_plotly_interactive(attack_graph, "interactive_attack_graph.html")
    generate_summary_report(
        suricata_alerts, 
        zeek_connections, 
        packet_flows, 
        "security_summary.html"
    )
    
    print("[+] All visualizations generated successfully!")
    print(f"[+] Output directory: {os.path.abspath(GRAPH_OUTPUT_DIR)}")
