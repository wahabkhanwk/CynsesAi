from transformers import AutoTokenizer, AutoModelForSequenceClassification
from torch.nn import CrossEntropyLoss
from torch.optim import Adam
import torch
from scapy.all import *
from scapy.layers.inet import IP, TCP
import os
#from config.settings import PCAP_FILE

# List of output classes
classes = [
    'Analysis', 'Backdoor', 'Bot', 'DDoS', 'DoS', 'DoS GoldenEye', 'DoS Hulk',
    'DoS SlowHTTPTest', 'DoS Slowloris', 'Exploits', 'FTP Patator', 'Fuzzers',
    'Generic', 'Heartbleed', 'Infiltration', 'Normal', 'Port Scan', 'Reconnaissance',
    'SSH Patator', 'Shellcode', 'Web Attack - Brute Force', 'Web Attack - SQL Injection',
    'Web Attack - XSS', 'Worms'
]

# Load pre-trained model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("rdpahalavan/bert-network-packet-flow-header-payload")
model = AutoModelForSequenceClassification.from_pretrained("rdpahalavan/bert-network-packet-flow-header-payload")

# Dictionary to store attack counts
packets_brief = {}

# Set device to GPU if available
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
model = model.to(device)

def processing_packet_conversion(packet):
    """Converts packet fields into a string of decimal features."""
    packet_2 = packet
    while packet_2:
        layer = packet_2[0]
        packet_2 = layer.payload if layer.payload else None

    try:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet.sport
        dst_port = packet.dport
        ip_length = len(packet[IP])
        ip_ttl = packet[IP].ttl
        ip_tos = packet[IP].tos
        tcp_data_offset = packet[TCP].dataofs
        tcp_flags = int(packet[TCP].flags)
        payload_bytes = bytes(packet.payload)
        payload_length = len(payload_bytes)
        payload_decimal = ' '.join(str(byte) for byte in payload_bytes)

        final_data = f"0 0 195 -1 {src_port} {dst_port} {ip_length} {payload_length} {ip_ttl} {ip_tos} {tcp_data_offset} {tcp_flags} -1 {payload_decimal}"
        return final_data
    except Exception as e:
        print(f"[ERROR] Packet conversion failed: {e}")
        return None

def predictingRowsCategory(file_path, filter_payload=None, debug=False):
    """Predicts class of each packet in the pcap file on CPU."""
    packets_brief.clear()
    packets_nbr = 0

    with PcapReader(file_path) as pcap:
        for pkt in pcap:
            if IP in pkt and TCP in pkt:
                if filter_payload:
                    payload_bytes_to_filter = bytes(pkt.payload)
                    if filter_payload not in payload_bytes_to_filter:
                        continue

                input_line = processing_packet_conversion(pkt)
                if input_line is not None:
                    truncated_line = input_line[:1024]
                    tokens = tokenizer(truncated_line, return_tensors="pt")
                    tokens = {key: value.to(device) for key, value in tokens.items()}
                    outputs = model(**tokens)

                    logits = outputs.logits
                    probabilities = logits.softmax(dim=1)
                    predicted_class = torch.argmax(probabilities, dim=1).item()
                    predicted_attack = classes[predicted_class]

                    if predicted_attack != "Normal":
                        packets_brief[predicted_attack] = packets_brief.get(predicted_attack, 0) + 1

                    if debug:
                        print(f"Predicted class index: {predicted_class}")
                        print(f"Predicted class: {predicted_attack}")
                        print(f"Class probabilities: {probabilities.tolist()}")

                packets_nbr += 1

    print(f"\nTotal packets processed: {packets_nbr}")
    print("Detected non-normal traffic:")
    for attack, count in packets_brief.items():
        print(f"{attack}: {count}")

def predictingRowsCategoryOnGPU(file_path, filter_payload=None, debug=False):
    """Predicts class of each packet in the pcap file on GPU."""
    packets_brief.clear()
    packets_nbr = 0

    with PcapReader(file_path) as pcap:
        for pkt in pcap:
            if IP in pkt and TCP in pkt:
                payload_bytes_to_filter = bytes(pkt.payload)
                if filter_payload and filter_payload not in payload_bytes_to_filter:
                    continue

                input_line = processing_packet_conversion(pkt)
                if input_line is not None:
                    truncated_line = input_line[:1024]
                    tokens = tokenizer(truncated_line, return_tensors="pt")
                    tokens = {key: value.to(device) for key, value in tokens.items()}
                    outputs = model(**tokens)

                    logits = outputs.logits
                    probabilities = logits.softmax(dim=1)
                    predicted_class = torch.argmax(probabilities, dim=1).item()
                    predicted_attack = classes[predicted_class]

                    if predicted_attack != "Normal":
                        packets_brief[predicted_attack] = packets_brief.get(predicted_attack, 0) + 1

                    if debug:
                        print(f"Predicted class index: {predicted_class}")
                        print(f"Predicted class: {predicted_attack}")
                        print(f"Class probabilities: {probabilities.tolist()}")

                packets_nbr += 1

    print(f"\nTotal packets processed: {packets_nbr}")
    print("Detected non-normal traffic:")
    for attack, count in packets_brief.items():
        print(f"{attack}: {count}")

# Optional: Function to exclude certain token indices before prediction
def predictingRowsCategoryOnGPUByGettingRidOfParameters(file_path, filter_payload=None, debug=False, tokens_to_exclude=[]):
    """Same as above but excludes specified token indices before prediction."""
    packets_brief.clear()
    packets_nbr = 0

    with PcapReader(file_path) as pcap:
        for pkt in pcap:
            if IP in pkt and TCP in pkt:
                payload_bytes_to_filter = bytes(pkt.payload)
                if filter_payload and filter_payload not in payload_bytes_to_filter:
                    continue

                input_line = processing_packet_conversion(pkt)
                if input_line is not None:
                    truncated_line = input_line[:1024]
                    tokens_list = truncated_line.split()
                    modified_tokens_list = [token for i, token in enumerate(tokens_list) if i not in tokens_to_exclude]
                    modified_truncated_line = ' '.join(modified_tokens_list)

                    tokens = tokenizer(modified_truncated_line, return_tensors="pt")
                    tokens = {key: value.to(device) for key, value in tokens.items()}
                    outputs = model(**tokens)

                    logits = outputs.logits
                    probabilities = logits.softmax(dim=1)
                    predicted_class = torch.argmax(probabilities, dim=1).item()
                    predicted_attack = classes[predicted_class]

                    if predicted_attack != "Normal":
                        packets_brief[predicted_attack] = packets_brief.get(predicted_attack, 0) + 1

                    if debug:
                        print(f"Predicted class index: {predicted_class}")
                        print(f"Predicted class: {predicted_attack}")
                        print(f"Class probabilities: {probabilities.tolist()}")

                packets_nbr += 1

    print(f"\nTotal packets processed: {packets_nbr}")
    print("Detected non-normal traffic:")
    for attack, count in packets_brief.items():
        print(f"{attack}: {count}")

#if __name__ == "__main__":
    # Example usage
#    predictingRowsCategoryOnGPU("/Users/macbook/Desktop/CynsesAI/GoldenEye.pcap", filter_payload=b"HTTP", debug=False)
