from flask import Flask, render_template, request, jsonify, send_file
import threading
import scapy.all as scapy
import pandas as pd
import os
import csv
from datetime import datetime
import networkx as nx
from pyvis.network import Network
import matplotlib.pyplot as plt
import pyfiglet

app = Flask(__name__)

# File paths
pcap_file = "static/captured_packets.pcap"
csv_file = "static/captured_packets.csv"

# Packet sniffing management
is_sniffing = False


# Packet capture handler
def packet_handler(packet):
    global pcap_file
    scapy.wrpcap(pcap_file, packet, append=True)


# Start sniffing in a separate thread
def start_sniffing():
    global is_sniffing
    is_sniffing = True
    scapy.sniff(prn=packet_handler, store=0, stop_filter=lambda _: not is_sniffing)


# Stop sniffing
def stop_sniffing():
    global is_sniffing
    is_sniffing = False


# Convert pcap to csv
def pcap_to_csv():
    packets = scapy.rdpcap(pcap_file)
    with open(csv_file, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "Source", "Destination", "Protocol", "Length"])
        for packet in packets:
            if scapy.IP in packet:
                timestamp = datetime.fromtimestamp(float(packet.time))
                src = packet[scapy.IP].src
                dst = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                length = len(packet)
                writer.writerow([timestamp, src, dst, proto, length])


# Analyze data using the provided script's logic
def analyze_data():
    data_file = pd.read_csv(csv_file)
    summary = {}

    # Top sources and destinations
    summary["Top Sources"] = data_file["Source"].value_counts().head(5).to_dict()
    summary["Top Destinations"] = (
        data_file["Destination"].value_counts().head(5).to_dict()
    )
    summary["Protocol Counts"] = data_file["Protocol"].value_counts().to_dict()

    # Generate a network graph (PyVis)
    network = nx.from_pandas_edgelist(
        data_file, source="Source", target="Destination", edge_attr=True
    )
    net = Network(notebook=False, height="1000px", width="1500px")
    net.from_nx(network)
    graph_file = "static/network_graph.html"
    net.save_graph(graph_file)

    # Generate protocol communication bar graph (Matplotlib)
    protocol_counts = data_file["Protocol"].value_counts()
    plt.bar(protocol_counts.index, protocol_counts.values, color="blue")
    plt.title("Protocol Communication Counts")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    bar_graph_file = "static/protocol_graph.png"
    plt.savefig(bar_graph_file)
    plt.close()

    return summary, graph_file, bar_graph_file


# ASCII banner for manual reference
def banner():
    return pyfiglet.figlet_format("Network Analyzer", font="starwars")


# Flask Routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/start_sniffing", methods=["POST"])
def start_sniffing_route():
    threading.Thread(target=start_sniffing).start()
    return jsonify({"status": "Sniffing started"})


@app.route("/stop_sniffing", methods=["POST"])
def stop_sniffing_route():
    stop_sniffing()
    pcap_to_csv()
    return jsonify({"status": "Sniffing stopped, data saved to pcap and csv"})


@app.route("/analyze_data", methods=["POST"])
def analyze_data_route():
    summary, graph_url, bar_graph_url = analyze_data()
    return jsonify(
        {"summary": summary, "graph_url": graph_url, "bar_graph_url": bar_graph_url}
    )


@app.route("/download/<file_type>", methods=["GET"])
def download(file_type):
    if file_type == "pcap":
        return send_file(
            pcap_file, as_attachment=True, download_name="captured_packets.pcap"
        )
    elif file_type == "csv":
        return send_file(
            csv_file, as_attachment=True, download_name="captured_packets.csv"
        )


if __name__ == "__main__":
    os.makedirs("static", exist_ok=True)
    app.run(debug=True, host="0.0.0.0", port=5000)
