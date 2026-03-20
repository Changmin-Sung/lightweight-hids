import time
from monitor import get_system_usage
from detector import detect_suspicious_process
from network import detect_suspicious_connections
from logger import log
import config


def calculate_risk(alerts):
    score = 0
    for alert in alerts:
        if "CPU" in alert:
            score += 2
        elif "Suspicious Process" in alert:
            score += 5
        elif "External Connection" in alert:
            score += 3
    return min(score, 10)


def get_risk_level(score):
    if score >= 7:
        return "HIGH"
    elif score >= 4:
        return "MEDIUM"
    else:
        return "LOW"


def main():
    print("HIDS started...\n")

    while True:
        usage = get_system_usage()
        alerts = []

        if usage["cpu"] > config.CPU_THRESHOLD:
            alerts.append(f"[High CPU] {usage['cpu']}%")

        if usage["ram"] > config.RAM_THRESHOLD:
            alerts.append(f"[High RAM] {usage['ram']}%")

        alerts += detect_suspicious_process()
        alerts += detect_suspicious_connections()

        print("\n=== SYSTEM STATUS ===")
        print(f"CPU: {usage['cpu']}% | RAM: {usage['ram']}%")

        if alerts:
            print("\n=== ALERTS ===")
            for alert in alerts:
                print(alert)
                log(alert)
        else:
            print("No suspicious activity detected.")

        risk_score = calculate_risk(alerts)
        risk_level = get_risk_level(risk_score)

        print("\n=== RISK ANALYSIS ===")
        print(f"Risk Level: {risk_level} ({risk_score}/10)")
        print(f"Total Alerts: {len(alerts)}")

        time.sleep(config.CHECK_INTERVAL)


if __name__ == "__main__":
    main()