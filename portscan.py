import socket
from concurrent.futures import ThreadPoolExecutor

import advisor

# Common home-network ports; scanning all 65535 would be slow and pointless.
# Every port here has an entry in advisor.py (what it is, the risk, how to close it).
COMMON_PORTS = sorted(advisor.ENTRIES)

# High and critical ports (flagged in alerts and on the dashboard); kept here for older imports.
RISKY_PORTS = advisor.RISKY_PORTS


def is_port_open(ip, port, timeout=0.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0


def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_ports(ip, ports=COMMON_PORTS, timeout=0.5, workers=50):
    """Return the open ports as [(port, service), ...]."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: is_port_open(ip, p, timeout), ports)
    return [(p, get_service_name(p)) for p, is_open in zip(ports, results) if is_open]

# --- Janus (optional engine) -----------------------------------------------------------------
# With the Janus scanner (https://github.com/fas0ftware/janus) installed, Lynceus asks every
# open port what really answers there (janus --sv) instead of trusting the port number:
# "OpenSSH 9.6p1" on 2222, a web server on 8080. Without it the built-in scan is used.

import ipaddress  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402  # fixed argument lists, never a shell  # nosec B404

from config import env  # noqa: E402

JANUS_TIMEOUT = 120
MAX_VERSION = 120
_janus_failed = False


def janus_binary():
    """LYNCEUS_JANUS, else `janus` on PATH, else a Janus checkout next to this one; None when
    there is none or LYNCEUS_ENGINE=builtin."""
    if env("ENGINE", "auto").lower() == "builtin":
        return None
    explicit = env("JANUS")
    candidates = [explicit] if explicit else [shutil.which("janus"),
                                              os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                           "..", "Janus", "janus")]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return None


def _clean(text, limit=MAX_VERSION):
    """Devices write these strings: keep them printable and short."""
    text = "" if text is None else str(text)
    return "".join(ch if ch.isprintable() else "?" for ch in text)[:limit]


def parse_janus(text):
    """[(port, service, version), ...] from `janus --sv --json` for one host."""
    data = json.loads(text)
    hosts = data.get("hosts", [data]) if isinstance(data, dict) else []
    out = []
    for host in hosts if isinstance(hosts, list) else []:
        for p in (host.get("open_ports") or []) if isinstance(host, dict) else []:
            port = p.get("port") if isinstance(p, dict) else None
            if not isinstance(port, int) or not 0 < port < 65536:
                continue
            d = p.get("detected") if isinstance(p.get("detected"), dict) else {}
            service = _clean(d.get("service") or p.get("service") or "", 32)
            if not service or service == "unknown":
                service = get_service_name(port)
            product, version, info = (_clean(d.get(k), 64) for k in ("product", "version", "info"))
            head = " ".join(x for x in (product, version) if x)
            line = f"{head} ({info})" if head and info else head or info
            out.append((port, service, line[:MAX_VERSION]))
    return sorted(set(out))


def scan_ports_janus(ip, binary, ports=COMMON_PORTS, timeout_ms=500):
    ip = str(ipaddress.IPv4Address(ip))      # only a plain address ever reaches the command line
    argv = [binary, "-t", ip, "-p", ",".join(str(int(p)) for p in ports), "--sv", "--json", "-4",
            "--timeout", str(int(timeout_ms))]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=JANUS_TIMEOUT, check=False)  # nosec B603
    # 0 = done, 130 = interrupted (partial JSON is still valid)
    if proc.returncode not in (0, 130) or not proc.stdout.strip():
        last = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"exit {proc.returncode}"
        raise RuntimeError(f"Janus failed: {_clean(last, 200)}")
    try:
        return parse_janus(proc.stdout)
    except ValueError as exc:
        raise RuntimeError(f"Janus gave unreadable output: {exc}") from None


def scan_device(ip, ports=COMMON_PORTS):
    """The scan main.py uses: Janus when available (with what answers on each port),
    else the built-in connect scan. A failing Janus falls back for the rest of the run."""
    global _janus_failed
    binary = None if _janus_failed else janus_binary()
    if binary:
        try:
            return scan_ports_janus(ip, binary, ports)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            _janus_failed = True
            print(f"  (Janus not usable, using the built-in scan from now on: {exc})")
    return [(port, service, "") for port, service in scan_ports(ip, ports)]
