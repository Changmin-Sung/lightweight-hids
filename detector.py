import psutil

SAFE_PROCESSES = [
    "python", "chrome", "system",
    "launchd", "notificationcenter", "mds",
    "siri", "sync", "imk", "audio", "map",
    "kernel", "windowserver", "bluetoothd",
    "coreaudiod", "cfprefsd", "distnoted",
    "leagueclient", "leagueclientux"   
]

CPU_THRESHOLD = 50


def detect_suspicious_process():
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            name = proc.info['name'].lower()
            cpu = proc.info['cpu_percent']

            if name is None:
                continue

            if any(safe in name for safe in SAFE_PROCESSES):
                continue

            if cpu > CPU_THRESHOLD:
                suspicious.append(f"[Suspicious Process] {name} ({cpu}%)")

        except:
            continue

    return suspicious
