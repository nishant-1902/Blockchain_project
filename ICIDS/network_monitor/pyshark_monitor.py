import logging
import threading
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logger.warning("Pyshark not available. Using simulated packets.")

from .scapy_monitor import generate_simulated_packet


def capture_with_pyshark(interface="lo", timeout=60):
    """
    Capture packets using PyShark (Wireshark/tshark backend).
    
    Args:
        interface (str): Network interface to capture on.
        timeout (int): Capture timeout in seconds.
    
    Yields:
        dict: Parsed packet information.
    """
    if not PYSHARK_AVAILABLE:
        logger.warning("PyShark not available. Generating simulated packets.")
        import time
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            yield generate_simulated_packet()
            time.sleep(0.1)
        return
    
    try:
        logger.info(f"Starting PyShark capture on interface: {interface}")
        cap = pyshark.LiveCapture(interface=interface, timeout=timeout)
        
        for packet in cap.sniff_continuously(packet_count=0):
            try:
                parsed = parse_pyshark_packet(packet)
                if parsed:
                    yield parsed
            except Exception as e:
                logger.debug(f"Error parsing PyShark packet: {e}")
                continue
    except Exception as e:
        logger.error(f"Error in PyShark capture: {e}")
        logger.info("Falling back to simulated packets")
        import time
        for _ in range(100):
            yield generate_simulated_packet()
            time.sleep(0.1)


def parse_pyshark_packet(packet):
    """
    Extract network features from a PyShark packet object.
    
    Args:
        packet: PyShark packet object.
    
    Returns:
        dict: Extracted packet information or None if parsing fails.
    """
    try:
        packet_info = {
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Extract IP layer
        if hasattr(packet, "ip"):
            packet_info["src_ip"] = packet.ip.src
            packet_info["dst_ip"] = packet.ip.dst
            packet_info["src_bytes"] = int(packet.ip.len) if hasattr(packet.ip, "len") else 0
        else:
            return None
        
        # Determine protocol
        if hasattr(packet, "tcp"):
            packet_info["protocol"] = "tcp"
            packet_info["port"] = int(packet.tcp.dstport)
            packet_info["flags"] = _parse_pyshark_tcp_flags(packet.tcp)
            packet_info["dst_bytes"] = int(packet.tcp.len) if hasattr(packet.tcp, "len") else 0
        elif hasattr(packet, "udp"):
            packet_info["protocol"] = "udp"
            packet_info["port"] = int(packet.udp.dstport)
            packet_info["flags"] = "U"
            packet_info["dst_bytes"] = int(packet.udp.len) if hasattr(packet.udp, "len") else 0
        elif hasattr(packet, "icmp"):
            packet_info["protocol"] = "icmp"
            packet_info["port"] = 0
            packet_info["flags"] = "ICMP"
            packet_info["dst_bytes"] = 0
        else:
            return None
        
        packet_info["size"] = int(packet.length)
        packet_info["duration"] = 0
        
        return packet_info
    except Exception as e:
        logger.debug(f"Error parsing PyShark packet: {e}")
        return None


def _parse_pyshark_tcp_flags(tcp_layer):
    """
    Parse TCP flags from PyShark TCP layer.
    
    Args:
        tcp_layer: PyShark TCP layer object.
    
    Returns:
        str: TCP flags string.
    """
    flags = ""
    try:
        if hasattr(tcp_layer, "flags"):
            flags_val = int(tcp_layer.flags, 16)
            if flags_val & 0x02:  # SYN
                flags += "S"
            if flags_val & 0x10:  # ACK
                flags += "A"
            if flags_val & 0x01:  # FIN
                flags += "F"
            if flags_val & 0x04:  # RST
                flags += "R"
            if flags_val & 0x08:  # PSH
                flags += "P"
    except Exception as e:
        logger.debug(f"Error parsing TCP flags: {e}")
    
    return flags or "SF"


def analyze_traffic_pattern(packets):
    """
    Analyze patterns in a list of packets to detect anomalies.
    
    Args:
        packets (list): List of parsed packet dictionaries.
    
    Returns:
        dict: Analysis results including patterns and anomalies.
    """
    if not packets:
        return {"error": "No packets to analyze"}
    
    analysis = {
        "total_packets": len(packets),
        "unique_src_ips": set(),
        "unique_dst_ips": set(),
        "protocol_distribution": defaultdict(int),
        "port_distribution": defaultdict(int),
        "total_bytes": 0,
        "anomalies": [],
    }
    
    try:
        for packet in packets:
            analysis["unique_src_ips"].add(packet.get("src_ip", "unknown"))
            analysis["unique_dst_ips"].add(packet.get("dst_ip", "unknown"))
            analysis["protocol_distribution"][packet.get("protocol", "unknown")] += 1
            analysis["port_distribution"][packet.get("port", 0)] += 1
            analysis["total_bytes"] += packet.get("size", 0)
        
        # Convert sets to lists for JSON serialization
        analysis["unique_src_ips"] = list(analysis["unique_src_ips"])
        analysis["unique_dst_ips"] = list(analysis["unique_dst_ips"])
        analysis["protocol_distribution"] = dict(analysis["protocol_distribution"])
        analysis["port_distribution"] = dict(analysis["port_distribution"])
        
        # Detect patterns
        analysis["anomalies"] = _detect_patterns(analysis, packets)
        
        logger.info(f"Traffic analysis complete: {len(packets)} packets analyzed")
        return analysis
    except Exception as e:
        logger.error(f"Error in traffic pattern analysis: {e}")
        return {"error": str(e)}


def _detect_patterns(analysis, packets):
    """
    Detect specific traffic patterns that indicate anomalies.
    
    Args:
        analysis (dict): Current analysis results.
        packets (list): List of packets.
    
    Returns:
        list: List of detected anomalies.
    """
    anomalies = []
    
    # Check for port scanning (many destinations on same src IP)
    src_to_dests = defaultdict(set)
    for packet in packets:
        src_to_dests[packet.get("src_ip")].add(packet.get("dst_ip"))
    
    for src_ip, dests in src_to_dests.items():
        if len(dests) > 50:
            anomalies.append({
                "type": "Port scanning",
                "severity": "High",
                "description": f"Source {src_ip} connected to {len(dests)} destinations",
            })
    
    # Check for data exfiltration (large outgoing bytes)
    src_bytes = defaultdict(int)
    for packet in packets:
        src_bytes[packet.get("src_ip")] += packet.get("src_bytes", 0)
    
    for src_ip, total_bytes in src_bytes.items():
        if total_bytes > 10 * 1024 * 1024:  # 10 MB threshold
            anomalies.append({
                "type": "Data exfiltration",
                "severity": "High",
                "description": f"Source {src_ip} transferred {total_bytes / (1024 * 1024):.2f} MB",
            })
    
    # Check for unusual protocols
    if analysis["protocol_distribution"].get("icmp", 0) > len(packets) * 0.5:
        anomalies.append({
            "type": "ICMP flood",
            "severity": "Medium",
            "description": f"Unusually high ICMP traffic ({analysis['protocol_distribution']['icmp']} packets)",
        })
    
    return anomalies


def detect_anomaly(packet_list):
    """
    Detect anomalies in a batch of packets using statistical methods.
    
    Args:
        packet_list (list): List of packet dictionaries.
    
    Returns:
        dict: Anomaly detection results.
    """
    if not packet_list:
        return {"status": "no_packets", "anomalies": []}
    
    results = {
        "total_packets": len(packet_list),
        "anomalies": [],
        "risk_score": 0.0,
    }
    
    try:
        # Analyze traffic patterns
        pattern_analysis = analyze_traffic_pattern(packet_list)
        results["pattern_analysis"] = pattern_analysis
        
        if "anomalies" in pattern_analysis:
            results["anomalies"].extend(pattern_analysis["anomalies"])
        
        # Calculate risk score based on anomalies
        critical_count = sum(1 for a in results["anomalies"] if a.get("severity") == "Critical")
        high_count = sum(1 for a in results["anomalies"] if a.get("severity") == "High")
        medium_count = sum(1 for a in results["anomalies"] if a.get("severity") == "Medium")
        
        results["risk_score"] = min(1.0, (critical_count * 0.5 + high_count * 0.3 + medium_count * 0.1) / len(packet_list))
        
        logger.info(f"Anomaly detection complete. Risk score: {results['risk_score']:.2f}")
        return results
    except Exception as e:
        logger.error(f"Error in anomaly detection: {e}")
        results["error"] = str(e)
        return results
