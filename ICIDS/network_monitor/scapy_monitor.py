import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, IP, ICMP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Using simulated packets.")


def generate_simulated_packet():
    """Generate a simulated network packet for testing without live capture."""
    import random
    
    protocols = ["tcp", "udp", "icmp"]
    flags = ["SF", "S0", "REJ", "RSTO", "RSTOS0", "RSTR", "S1", "S2", "S3", "SH"]
    
    protocol = random.choice(protocols)
    src_ip = f"192.168.1.{random.randint(1, 254)}"
    dst_ip = f"10.0.0.{random.randint(1, 254)}"
    port = random.choice([22, 80, 443, 3306, 5432, 8080, 8443, 53, 25, 110])
    
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "port": port,
        "size": random.randint(64, 1500),
        "flags": random.choice(flags),
        "timestamp": datetime.utcnow().isoformat(),
        "src_bytes": random.randint(0, 100000),
        "dst_bytes": random.randint(0, 100000),
        "duration": random.randint(0, 3600),
    }


def capture_with_scapy(interface="lo", count=0, timeout=60):
    """
    Capture packets using Scapy library.
    
    Args:
        interface (str): Network interface to capture on.
        count (int): Number of packets to capture (0 = unlimited).
        timeout (int): Capture timeout in seconds.
    
    Yields:
        dict: Parsed packet information.
    """
    if not SCAPY_AVAILABLE:
        logger.warning("Scapy not available. Generating simulated packets.")
        import time
        for _ in range(count or 100):
            yield generate_simulated_packet()
            time.sleep(0.1)
        return
    
    try:
        def packet_callback(packet):
            parsed = parse_packet(packet)
            if parsed:
                yield parsed
        
        logger.info(f"Starting Scapy capture on interface: {interface}")
        sniff(
            iface=interface,
            prn=lambda p: packet_callback(p),
            store=False,
            count=count,
            timeout=timeout,
        )
    except Exception as e:
        logger.error(f"Error in Scapy capture: {e}")
        logger.info("Falling back to simulated packets")
        import time
        for _ in range(count or 100):
            yield generate_simulated_packet()
            time.sleep(0.1)


def parse_packet(packet):
    """
    Extract relevant network features from a captured packet.
    
    Args:
        packet: Scapy packet object.
    
    Returns:
        dict: Extracted packet information or None if parsing fails.
    """
    try:
        packet_info = {
            "timestamp": datetime.utcnow().isoformat(),
            "size": len(packet),
        }
        
        # Extract IP layer information
        if IP in packet:
            ip_layer = packet[IP]
            packet_info["src_ip"] = ip_layer.src
            packet_info["dst_ip"] = ip_layer.dst
            packet_info["protocol"] = "tcp" if ip_layer.proto == 6 else "udp" if ip_layer.proto == 17 else "icmp"
            packet_info["src_bytes"] = ip_layer.len if hasattr(ip_layer, "len") else 0
        
        # Extract TCP information
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info["port"] = tcp_layer.dport
            packet_info["flags"] = _parse_tcp_flags(tcp_layer)
            packet_info["protocol"] = "tcp"
        
        # Extract UDP information
        elif UDP in packet:
            udp_layer = packet[UDP]
            packet_info["port"] = udp_layer.dport
            packet_info["flags"] = "U"
            packet_info["protocol"] = "udp"
        
        # ICMP
        elif ICMP in packet:
            packet_info["protocol"] = "icmp"
            packet_info["flags"] = "ICMP"
            packet_info["port"] = 0
        
        return packet_info if packet_info.get("src_ip") else None
    except Exception as e:
        logger.debug(f"Error parsing packet: {e}")
        return None


def _parse_tcp_flags(tcp_layer):
    """
    Parse TCP flags from TCP layer.
    
    Args:
        tcp_layer: Scapy TCP layer object.
    
    Returns:
        str: TCP flags string.
    """
    flags = ""
    if hasattr(tcp_layer, "flags"):
        if tcp_layer.flags.S:
            flags += "S"
        if tcp_layer.flags.A:
            flags += "A"
        if tcp_layer.flags.F:
            flags += "F"
        if tcp_layer.flags.R:
            flags += "R"
        if tcp_layer.flags.P:
            flags += "P"
        if tcp_layer.flags.syn:
            flags = "S"
        if tcp_layer.flags.ack and not flags:
            flags = "A"
    
    return flags or "SF"


def filter_suspicious(packet):
    """
    Apply basic rule-based filtering to identify suspicious packets.
    
    Rules:
    - Land attack (src_ip == dst_ip)
    - Unusually large packets
    - Uncommon ports
    - Connection without proper flags
    
    Args:
        packet (dict): Parsed packet information.
    
    Returns:
        dict: Contains 'is_suspicious' bool and 'reasons' list.
    """
    reasons = []
    is_suspicious = False
    
    # Check for land attack
    if packet.get("src_ip") == packet.get("dst_ip"):
        reasons.append("Land attack detected (same src and dst IP)")
        is_suspicious = True
    
    # Check for unusually large packets
    if packet.get("size", 0) > 65535:
        reasons.append("Unusually large packet")
        is_suspicious = True
    
    # Check for uncommon ports (possible port scanning)
    uncommon_ports = {1, 139, 445, 1433, 3389, 8888}
    if packet.get("port") in uncommon_ports:
        reasons.append(f"Suspicious port: {packet.get('port')}")
        is_suspicious = True
    
    # Check for invalid TCP flags
    if packet.get("protocol") == "tcp" and not packet.get("flags"):
        reasons.append("TCP packet without valid flags")
        is_suspicious = True
    
    return {
        "is_suspicious": is_suspicious,
        "reasons": reasons,
        "confidence": len(reasons) / 4.0,  # Simple confidence calculation
    }


def emit_to_socket(socketio, data, room=None):
    """
    Emit packet data to connected clients via SocketIO.
    
    Args:
        socketio: Flask-SocketIO instance.
        data (dict): Packet or analysis data to emit.
        room (str): Optional room to emit to. If None, broadcasts to all.
    
    Returns:
        bool: True if emission was successful.
    """
    try:
        if room:
            socketio.emit("packet_data", data, room=room)
        else:
            socketio.emit("packet_data", data, broadcast=True)
        
        logger.debug(f"Data emitted via SocketIO: {data.get('timestamp', 'N/A')}")
        return True
    except Exception as e:
        logger.error(f"Error emitting to SocketIO: {e}")
        return False


def process_packet_stream(interface="lo", count=100, socketio=None):
    """
    Process a stream of packets and emit results.
    
    Args:
        interface (str): Network interface.
        count (int): Number of packets to process.
        socketio: Optional Flask-SocketIO instance for real-time updates.
    
    Yields:
        dict: Processed packet information.
    """
    for packet in capture_with_scapy(interface, count):
        suspicion = filter_suspicious(packet)
        packet["suspicion"] = suspicion
        
        if socketio:
            emit_to_socket(socketio, packet)
        
        yield packet
