import psutil

def detect_suspicious_connections():
    alerts = []

    try:
        connections = psutil.net_connections(kind='inet')

        for conn in connections:
            if conn.raddr:
                ip = conn.raddr.ip

                if not ip.startswith("192.") and not ip.startswith("127."):
                    alerts.append(f"[External Connection] {ip}")

    except Exception:
        return []

    return alerts
