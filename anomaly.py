def detect_anomalies(current, baseline, cfg):
    alerts = []

    for ip, data in current.items():
        if ip not in baseline:
            alerts.append(f"new IP detected: {ip}")
            continue

        base_total = baseline[ip]["total"]

        if data["total"] > base_total * cfg.MAX_PACKETS_FACTOR:
            alerts.append(
                f"High traffic with {ip}: {data['total']} packets"
            )

        base_ports = set(baseline[ip]["ports"].keys())
        new_ports = set(data["ports"].keys()) - base_ports

        if new_ports:
            alerts.append(
                f"New port with {ip}: {list(new_ports)}"
            )

    return alerts