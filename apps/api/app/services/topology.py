"""Synthetic enterprise network used by SIMULATION mode.

Everything produced here is synthetic and labelled as such by the API (``source: simulation``).
The topology is deterministic for a given seed so tests and demos are reproducible.
"""

import random
from dataclasses import dataclass, field


@dataclass
class DeviceSpec:
    hostname: str
    device_type: str  # internet|firewall|router|server|database|workstation|iot|cloud
    role: str
    os: str
    zone: str
    criticality: int
    ports: list[int]
    protocols: list[str]
    baseline: dict = field(default_factory=dict)
    current: dict = field(default_factory=dict)
    ip: str = ""
    mac: str = ""
    position: dict = field(default_factory=dict)


def _bl(dns, http, ssh, up, new):
    rng = lambda hi: {"min": round(hi * 0.4), "max": hi}  # noqa: E731
    return {
        "dns_per_hour": rng(dns),
        "http_per_hour": rng(http),
        "ssh_per_hour": {"min": 0, "max": ssh},
        "upload_mb_per_day": {"min": 0, "max": up},
        "new_destinations_per_day": {"min": 0, "max": new},
    }


# Hand-placed anomalous devices so the demo has something to find. Their "current" values
# are written into the behavior profile; scoring then derives risk from them transparently.
_SCENARIO = {
    "PC-07": {"dns_per_hour": 1240, "http_per_hour": 44, "ssh_per_hour": 48,
              "upload_mb_per_day": 1200, "new_destinations_per_day": 17},
    "CAM-02": {"dns_per_hour": 160, "http_per_hour": 4, "ssh_per_hour": 0,
               "upload_mb_per_day": 640, "new_destinations_per_day": 6},
    "DB-02": {"dns_per_hour": 22, "http_per_hour": 0, "ssh_per_hour": 9,
              "upload_mb_per_day": 310, "new_destinations_per_day": 3},
    "JUMP-01": {"dns_per_hour": 55, "http_per_hour": 20, "ssh_per_hour": 18,
                "upload_mb_per_day": 40, "new_destinations_per_day": 4},
    "PC-12": {"dns_per_hour": 190, "http_per_hour": 90, "ssh_per_hour": 1,
              "upload_mb_per_day": 95, "new_destinations_per_day": 4},
}


def build_devices(seed: int) -> list[DeviceSpec]:
    rng = random.Random(seed)
    S = DeviceSpec
    d: list[DeviceSpec] = [
        S("INTERNET", "internet", "Untrusted external networks", "n/a", "external", 1, [], []),
        S("FW-01", "firewall", "Perimeter firewall", "FortiOS 7.4", "perimeter", 5, [443, 22], ["tcp", "udp"],
          _bl(30, 10, 2, 500, 3)),
        S("RTR-01", "router", "Core router", "Cisco IOS-XE", "core", 5, [22, 161], ["tcp", "udp", "snmp"],
          _bl(20, 0, 2, 200, 2)),
    ]
    for n, role in [("WEB-01", "Public web server"), ("WEB-02", "Public web server")]:
        d.append(S(n, "server", role, "Ubuntu 22.04", "dmz", 4, [80, 443], ["http", "tls"], _bl(60, 4000, 1, 8000, 5)))
    d.append(S("MAIL-01", "server", "Mail gateway", "Debian 12", "dmz", 4, [25, 587, 993], ["smtp", "imap"], _bl(120, 300, 1, 2000, 15)))
    d.append(S("DNS-01", "server", "Internal DNS resolver", "Ubuntu 22.04", "dmz", 4, [53], ["dns"], _bl(20000, 0, 1, 400, 40)))
    for i in range(1, 4):
        d.append(S(f"APP-0{i}", "server", "Application server", "Ubuntu 22.04", "internal", 3, [8080, 22], ["http", "ssh"], _bl(80, 2500, 4, 300, 4)))
    d.append(S("FILE-01", "server", "File server", "Windows Server 2022", "internal", 4, [445, 3389], ["smb", "rdp"], _bl(40, 20, 0, 600, 3)))
    d.append(S("AD-01", "server", "Domain controller", "Windows Server 2022", "internal", 5, [389, 88, 445], ["ldap", "kerberos"], _bl(300, 10, 0, 200, 5)))
    for i in range(1, 4):
        d.append(S(f"DB-0{i}", "database", "PostgreSQL database" if i != 3 else "Analytics database", "Ubuntu 22.04", "data", 5, [5432, 22], ["postgres", "ssh"], _bl(30, 0, 2, 120, 2)))
    for i in range(1, 19):
        d.append(S(f"PC-{i:02d}", "workstation", "Employee workstation", rng.choice(["Windows 11", "Windows 11", "Ubuntu 24.04", "macOS 14"]), "internal", 2, [135, 445], ["http", "tls", "dns", "smb"], _bl(70, 30, 2, 50, 5)))
    for n, role in [("CAM-01", "IP camera"), ("CAM-02", "IP camera"), ("CAM-03", "IP camera"),
                    ("PRN-01", "Network printer"), ("PRN-02", "Network printer"),
                    ("HVAC-01", "Building controller"), ("BADGE-01", "Badge reader")]:
        d.append(S(n, "iot", role, "Embedded Linux", "iot", 2, [80, 554], ["http", "rtsp"], _bl(25, 6, 0, 20, 1)))
    d.append(S("VPN-GW", "cloud", "Cloud VPN gateway", "Linux", "cloud", 4, [443, 500], ["tls", "ipsec"], _bl(15, 5, 2, 800, 3)))
    d.append(S("CLOUD-API-01", "cloud", "Cloud API service", "Linux", "cloud", 3, [443], ["tls"], _bl(40, 1500, 1, 3000, 6)))
    d.append(S("CLOUD-VM-01", "cloud", "Cloud compute instance", "Amazon Linux 2023", "cloud", 3, [22, 443], ["ssh", "tls"], _bl(50, 400, 6, 900, 8)))
    d.append(S("S3-BACKUP", "cloud", "Object storage (backups)", "n/a", "cloud", 4, [443], ["tls"], _bl(5, 20, 0, 5000, 1)))
    d.append(S("SIEM-LOG-01", "server", "Log collector", "Ubuntu 22.04", "internal", 4, [514, 9200], ["syslog", "http"], _bl(10, 30, 2, 100, 2)))
    d.append(S("JUMP-01", "server", "Bastion / jump host", "Ubuntu 22.04", "internal", 5, [22], ["ssh"], _bl(15, 5, 12, 60, 3)))
    d.append(S("ADMIN-WS-01", "workstation", "Administrator workstation", "Windows 11", "internal", 4, [3389], ["rdp", "ssh", "tls"], _bl(90, 40, 10, 80, 6)))

    # Addressing
    subnet = {"external": "203.0.113", "perimeter": "10.0.0", "core": "10.0.0", "dmz": "10.0.10",
              "internal": "10.0.20", "data": "10.0.30", "iot": "10.0.40", "cloud": "172.31.0"}
    counters: dict[str, int] = {}
    for dev in d:
        counters[dev.zone] = counters.get(dev.zone, 0) + 1
        host = counters[dev.zone]
        if dev.hostname == "FW-01":
            dev.ip = "10.0.0.1"
        elif dev.hostname == "RTR-01":
            dev.ip = "10.0.0.2"
        elif dev.hostname == "INTERNET":
            dev.ip = "203.0.113.1"
        else:
            dev.ip = f"{subnet[dev.zone]}.{10 + host}"
        dev.mac = ":".join(f"{rng.randrange(256):02x}" for _ in range(6))
        dev.current = {k: _jitter(rng, v["max"]) for k, v in dev.baseline.items()}
        if dev.hostname in _SCENARIO:
            dev.current = dict(_SCENARIO[dev.hostname])
    return d


def _jitter(rng: random.Random, upper: float) -> float:
    return round(upper * rng.uniform(0.35, 0.95), 1)


def layout(devices: list[DeviceSpec]) -> None:
    """Zone-banded layout so the topology reads like a network diagram, not a hairball.

    Zones that share a band sit on the same rows; bands wider than ROW_MAX nodes wrap so the
    overall aspect ratio stays roughly screen-shaped.
    """
    bands = [["external"], ["perimeter"], ["core"], ["dmz", "cloud"], ["internal"], ["data", "iot"]]
    row_max, dx, dy, band_gap = 12, 112, 90, 40
    y = 0.0
    for zones in bands:
        members = [d for d in devices if d.zone in zones]
        for r in range(0, len(members), row_max):
            chunk = members[r : r + row_max]
            for i, dev in enumerate(chunk):
                dev.position = {"x": round((i - (len(chunk) - 1) / 2) * dx), "y": round(y)}
            y += dy
        y += band_gap


def build_edges(devices: list[DeviceSpec], seed: int) -> list[dict]:
    rng = random.Random(seed + 1)
    by = {d.hostname: d for d in devices}
    edges: list[dict] = []

    def add(a, b, proto, port, bph, cph, suspicious=False):
        edges.append({"src": a, "dst": b, "protocol": proto, "port": port,
                      "bytes_per_hour": bph, "connections_per_hour": cph, "suspicious": suspicious})

    add("INTERNET", "FW-01", "tls", 443, 900_000_000, 4200)
    add("FW-01", "RTR-01", "ip", None, 880_000_000, 4100)
    for n in ("WEB-01", "WEB-02", "MAIL-01", "DNS-01", "VPN-GW", "CLOUD-API-01"):
        add("FW-01", n, "tls", 443, rng.randint(20, 300) * 1_000_000, rng.randint(200, 1800))
    for d in devices:
        if d.device_type == "workstation":
            add(d.hostname, "DNS-01", "dns", 53, rng.randint(40, 90) * 1000, rng.randint(40, 90))
            add(d.hostname, "AD-01", "kerberos", 88, rng.randint(1, 5) * 1_000_000, rng.randint(10, 40))
            add(d.hostname, "FILE-01", "smb", 445, rng.randint(5, 80) * 1_000_000, rng.randint(5, 60))
            add(d.hostname, "RTR-01", "tls", 443, rng.randint(10, 120) * 1_000_000, rng.randint(40, 300))
        if d.device_type == "iot":
            add(d.hostname, "RTR-01", "http", 80, rng.randint(1, 20) * 1_000_000, rng.randint(5, 40))
    for i in range(1, 4):
        add(f"APP-0{i}", "DB-01" if i < 3 else "DB-03", "postgres", 5432, rng.randint(50, 400) * 1_000_000, rng.randint(200, 900))
        add("WEB-01" if i % 2 else "WEB-02", f"APP-0{i}", "http", 8080, rng.randint(20, 120) * 1_000_000, rng.randint(300, 1500))
    add("RTR-01", "APP-01", "http", 8080, 60_000_000, 500)
    add("DB-01", "S3-BACKUP", "tls", 443, 180_000_000, 12)
    add("ADMIN-WS-01", "JUMP-01", "ssh", 22, 4_000_000, 14)
    add("JUMP-01", "APP-02", "ssh", 22, 2_000_000, 6)
    add("JUMP-01", "DB-01", "ssh", 22, 1_500_000, 4)
    add("JUMP-01", "CLOUD-VM-01", "ssh", 22, 1_000_000, 3)
    add("RTR-01", "SIEM-LOG-01", "syslog", 514, 30_000_000, 900)
    add("RTR-01", "FILE-01", "smb", 445, 40_000_000, 80)

    # Scenario edges: these are what makes the simulated network look "interesting".
    add("PC-07", "JUMP-01", "ssh", 22, 90_000_000, 480, True)
    add("PC-07", "DB-02", "postgres", 5432, 310_000_000, 90, True)
    add("PC-07", "INTERNET", "tls", 443, 1_200_000_000, 150, True)
    add("CAM-02", "INTERNET", "tcp", 8443, 640_000_000, 40, True)
    add("DB-02", "INTERNET", "tls", 443, 310_000_000, 18, True)
    add("PC-12", "RTR-01", "tls", 443, 95_000_000, 280)
    assert all(e["src"] in by and e["dst"] in by for e in edges)
    # One edge per (src, dst, protocol); later entries (scenario overrides) win.
    return list({(e["src"], e["dst"], e["protocol"]): e for e in edges}.values())
