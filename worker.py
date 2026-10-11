#!/usr/bin/env python
"""TokenBroker compute worker (opaque node).

The worker is a black box with a viewing window:
  - prompts arrive over HTTPS, are held in memory only, and are NEVER written
    to disk or shown in full (the stats window shows a redacted preview);
  - model output is rewrapped and returned to the hub; the worker never logs
    or displays the generated content, only token counts and cost;
  - a local stats window (http://127.0.0.1:8765) shows status, timestamps,
    CPU/GPU usage, jobs, tokens, and earnings.

Usage (normally installed via install.bat - no command line needed):
  python worker.py --config worker-config.json
or
  python worker.py --gateway https://... --token tb_node_...
"""

import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import threading
import time
import traceback
import uuid
from urllib.parse import urlparse, parse_qs
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _hidden_startupinfo():
    """SW_HIDE startup info so child processes never flash a window."""
    if not sys.platform.startswith("win"):
        return None
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        return si
    except Exception:
        return None


def _run(args, **kwargs):
    """subprocess.run that never flashes a console window on Windows.

    The worker is a windowed app (PyInstaller --noconsole), but child console
    processes (nvidia-smi, powershell, ollama) would otherwise pop a cmd
    window on every heartbeat. CREATE_NO_WINDOW + SW_HIDE keep everything
    invisible.

    Text-mode captures are decoded as UTF-8 (undecodable bytes replaced):
    `ollama pull` emits progress glyphs the Windows ANSI codepage can't
    decode, which otherwise kills the capture reader thread.
    """
    if kwargs.get("text") or kwargs.get("universal_newlines"):
        kwargs.setdefault("encoding", "utf-8")
        kwargs.setdefault("errors", "replace")
    if sys.platform.startswith("win"):
        kwargs.setdefault(
            "creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
        kwargs.setdefault("startupinfo", _hidden_startupinfo())
    return subprocess.run(args, **kwargs)


def _popen_hidden(args, **kwargs):
    """subprocess.Popen that never flashes a console window (Windows)."""
    if sys.platform.startswith("win"):
        kwargs.setdefault(
            "creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
        kwargs.setdefault("startupinfo", _hidden_startupinfo())
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.STDOUT)
    kwargs.setdefault("text", True)
    return subprocess.Popen(args, **kwargs)


OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
STATS_PORT = int(os.environ.get("WORKER_STATS_PORT", "8765"))
STATS_TOKEN = secrets.token_hex(8)


def crash_log_path():
    return os.path.join(app_dir(), "worker-crash.log")


def _log_crash(text):
    try:
        with open(crash_log_path(), "a") as f:
            f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}\n")
    except Exception:
        pass


def _show_error(text):
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(0, text, "TokenBroker Worker", 0x10)
    except Exception:
        pass


def crash_hook(exc_type, exc_value, exc_tb):
    detail = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    _log_crash(detail)
    try:
        # Also surface it on stderr: headless/CI runs only see the console.
        sys.stderr.write(detail)
        sys.stderr.flush()
    except Exception:
        pass
    if getattr(sys, "frozen", False):
        _show_error(
            "TokenBroker worker hit an unexpected error and stopped.\n\n"
            f"Details were saved to:\n{crash_log_path()}"
        )


sys.excepthook = crash_hook


def app_dir():
    """Directory the worker lives in: beside the exe when frozen, else cwd."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

STATE = {
    "status": "starting",
    "gpu": None,
    "cpu_pct": 0.0,
    "uptime_s": 0,
    "started_at": time.time(),
    "models": [],
    "heartbeats": 0,
    "last_heartbeat_at": None,
    "jobs_completed": 0,
    "jobs_failed": 0,
    "tokens": 0,
    "credits": 0,
    "credits_tier": None,
    "last_job": None,  # {id, model, kind, redacted_prompt, started_at, finished_at, latency_ms}
    "last_error": None,
    "private_mode": False,
    "private_jobs": True,
    "job_history": [],
    "_last_tokens": 0,
    "storage_gb": 20,
    "gateway": None,
    "fingerprint": None,
    "vm": {"score": 0, "reasons": []},
    "quality": None,
    "worker_hash": None,
    "worker_verified": None,
    "history": [],
    # Keys for non-Ollama cloud providers (Google AI Studio, Mistral AI
    # Studio, ...) synced down from the hub's heartbeat response - see
    # EXTERNAL_PROVIDERS below and the provider_keys sync in worker_loop.
    "provider_keys": {},
    "rpm": 0,
    "pool": {},
    "pool_count": 0,
    "pool_mb": 0,
    "pool_evictions": 0,
    "max_pool_idle_hours": 2,
    "cloud": {
        "enabled": False,
        "auth_ok": None,
        # An account-wide (or per-node) key synced down from the hub's
        # heartbeat response - see api_key sync-down below. Used only as a
        # fallback direct call to ollama.com when this machine's local
        # `ollama signin` session isn't authenticated (auth_ok is not True):
        # if signin already works, the existing local-proxy path is used
        # unchanged, since it needs no key at all.
        "api_key": None,
        "used_tokens_per_hour": 0,
        "quota_per_hour": 100000,
        "remaining": 100000,
        "login": None,
        "account": None,
        "installed": None,
        "total_tokens": 0,
        "subscription": None,
        "paywalled": [],
        # Set only by a REAL rejection from Ollama (classify_cloud_error ==
        # 'quota'), never by our own self-imposed hourly pacing budget above.
        # real_limit_hit_tokens is the empirical answer to "how many tokens
        # can this account actually generate" - Ollama exposes no API for
        # it, so this is the only way to ever learn a real number.
        "real_limit_hit": False,
        "real_limit_hit_at": None,
        "real_limit_hit_tokens": None,
        "real_limit_cleared_at": None,
    },
}

# After a real quota rejection, stop advertising cloud models for this long
# before trying again (one probe job). Too short risks repeatedly hammering
# a still-exhausted account (the automation/ToS risk); too long leaves
# capacity idle after Ollama's real reset. Ollama's reset cadence is
# monthly-from-signup and unpublished per-account, so this is a compromise,
# not a known-correct value.
CLOUD_LIMIT_RETRY_COOLDOWN_S = 6 * 60 * 60


def cloud_real_limit_active():
    """True while a real (not self-imposed) quota rejection is still in its
    cooldown window - advertised_models() uses this to stop offering cloud
    models until one probe job is allowed through again."""
    c = STATE["cloud"]
    if not c.get("real_limit_hit") or not c.get("real_limit_hit_at"):
        return False
    return (time.time() - c["real_limit_hit_at"]) < CLOUD_LIMIT_RETRY_COOLDOWN_S

PAUSE_EVENT = threading.Event()
STOP_EVENT = threading.Event()

def _win_hw_python():
    """Pure-Python Windows hardware gatherer - no PowerShell, no popups."""
    info = {
        "manufacturer": None, "model": None, "hypervisor": None,
        "biosMan": None, "biosSer": None, "cpu": platform.processor(),
        "cpuId": None, "cores": os.cpu_count() or 0,
        "ramGb": round_ram(), "boardSer": None, "guid": None,
        "macs": str(uuid.getnode()), "disks": "", "diskSers": "",
    }
    try:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                info["guid"] = winreg.QueryValueEx(k, "MachineGuid")[0]
        except Exception:
            pass
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
                info["cpu"] = winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
                info["cpuId"] = winreg.QueryValueEx(k, "Identifier")[0].strip()
        except Exception:
            pass
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as k:
                info["biosMan"] = winreg.QueryValueEx(k, "BIOSVendor")[0]
                info["biosSer"] = winreg.QueryValueEx(k, "BIOSSerialNumber")[0]
                info["boardSer"] = winreg.QueryValueEx(k, "SystemSerialNumber")[0]
                info["manufacturer"] = winreg.QueryValueEx(k, "SystemManufacturer")[0]
                info["model"] = winreg.QueryValueEx(k, "SystemProductName")[0]
        except Exception:
            pass
    except Exception:
        pass
    try:
        import psutil
        macs = []
        for _name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(psutil, "AF_LINK", None) is not None and a.family == psutil.AF_LINK and a.address and a.address.lower() != "00:00:00:00:00:00":
                    macs.append(a.address)
        info["macs"] = ",".join(dict.fromkeys(macs))[:400]
        disks = []
        try:
            for part in psutil.disk_partitions(all=True):
                disks.append(part.device)
        except Exception:
            pass
        info["disks"] = ",".join(disks)[:400]
    except Exception:
        pass
    return info


def _read(path):
    """Best-effort text read of a sysfs/procfs file ('' if missing or unreadable)."""
    try:
        with open(path, "r", errors="replace") as f:
            return f.read().strip()
    except Exception:
        return ""


def gather_hw():
    if sys.platform.startswith("win"):
        info = _win_hw_python()
        if info:
            return info
        return {
            "manufacturer": None,
            "model": None,
            "hypervisor": None,
            "biosMan": None,
            "biosSer": None,
            "cpu": platform.processor(),
            "cores": os.cpu_count() or 0,
            "ramGb": round_ram(),
            "cpuId": None,
            "boardSer": None,
            "guid": None,
            "macs": str(uuid.getnode()),
            "disks": "",
            "diskSers": "",
        }
    return {
        "manufacturer": _read("/sys/class/dmi/id/sys_vendor"),
        "model": _read("/sys/class/dmi/id/product_name"),
        "hypervisor": None,
        "biosMan": _read("/sys/class/dmi/id/bios_vendor"),
        "biosSer": _read("/sys/class/dmi/id/board_serial"),
        "cpu": platform.processor(),
        "cores": os.cpu_count() or 0,
        "ramGb": round_ram(),
        "cpuId": _read("/proc/cpuinfo")[:200],
        "boardSer": _read("/sys/class/dmi/id/board_serial"),
        "guid": _read("/etc/machine-id"),
        "macs": str(uuid.getnode()),
        "disks": "",
        "diskSers": "",
    }


def round_ram():
    try:
        if sys.platform.startswith("win"):
            try:
                import ctypes
                class _MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]
                m = _MEMORYSTATUSEX()
                m.dwLength = ctypes.sizeof(m)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                    return round(m.ullTotalPhys / (1024 ** 3), 1)
            except Exception:
                pass
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    return round(int(line.split()[1]) / 1024 / 1024, 1)
    except Exception:
        pass
    return 0.0


def hardware_fingerprint():
    info = gather_hw()
    raw = "|".join(
        str(info.get(k) or "")
        for k in ("guid", "cpuId", "boardSer", "macs", "diskSers")
    )
    return hashlib.sha256(raw.encode()).hexdigest(), info


def vm_detection(info):
    """Heuristic VM suspicion score (0-1). Threshold 0.5 = confident VM."""
    score = 0.0
    reasons = []

    def add(weight, reason):
        nonlocal score
        score = min(1.0, score + weight)
        reasons.append(reason)

    blob = " ".join(
        str(info.get(k) or "")
        for k in ("manufacturer", "model", "biosMan", "biosSer", "cpu", "disks")
    ).upper()
    for marker, weight in {
        "VMWARE": 0.4,
        "VIRTUALBOX": 0.4,
        "INNOTEK": 0.4,
        "QEMU": 0.4,
        "XEN": 0.4,
        "PARALLELS": 0.4,
        "KVM": 0.3,
        "VBOX": 0.4,
        "VIRTUAL MACHINE": 0.35,
        "HYPER-V": 0.3,
    }.items():
        if marker in blob:
            add(weight, marker)
    disks = str(info.get("disks", "")).upper()
    for marker in ("VBOX", "VMWARE", "QEMU", "VIRTUAL", "XEN"):
        if marker in disks:
            add(0.25, "disk:" + marker)
    vm_macs = (
        "00:0C:29",
        "00:50:56",
        "00:05:69",
        "08:00:27",
        "52:54:00",
        "00:16:3E",
        "00:1C:42",
        "00:03:FF",
        "00:15:5D",
    )
    for mac in str(info.get("macs", "")).upper().split(","):
        mac = mac.strip()
        for prefix in vm_macs:
            if mac.startswith(prefix):
                add(0.35, "mac:" + prefix)
                break
    if info.get("hypervisor"):
        add(0.1, "hypervisor-present")
    return {"score": round(min(1.0, score), 2), "reasons": reasons[:6]}


class HttpJsonError(Exception):
    """HTTPError with the status code + response body preserved, so callers
    can tell a real Ollama Cloud quota/rate-limit rejection apart from an
    auth failure or an unrelated error. str(err) still reads like a normal
    error message, so every existing `except Exception` / `str(err)` call
    site keeps working unchanged."""

    def __init__(self, status, body, url):
        self.status = status
        self.body = body or ""
        super().__init__(f"HTTP {status} from {url}: {self.body[:500]}")


def http_json(url, payload=None, method="POST", timeout=120):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            # Cloudflare's edge returns 403 for the default Python-urllib UA;
            # a descriptive product UA passes and stays honest about the client.
            "User-Agent": "TokenBrokerWorker/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode(errors="replace")
        except Exception:
            pass
        raise HttpJsonError(e.code, body, url) from e


def call_ollama_cloud_direct(api_key, model, messages, max_tokens=None, timeout=120):
    """Direct HTTPS call to Ollama's real cloud API, bearer-token
    authenticated - the same wire contract public/mobile-worker.html and the
    Android/iOS workers already use. Only reached when this machine has no
    working local `ollama signin` session but the hub synced down a key (see
    the api_key sync-down in worker_loop's heartbeat handling) - the normal,
    preferred path is still the local Ollama proxy below, which needs no key
    at all once actually signed in."""
    body = {"model": model, "messages": messages, "stream": False}
    if max_tokens:
        body["max_tokens"] = max_tokens
    req = urllib.request.Request(
        "https://ollama.com/api/chat",
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "TokenBrokerWorker/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        resp_body = ""
        try:
            resp_body = e.read().decode(errors="replace")
        except Exception:
            pass
        if e.code in (401, 403):
            # HttpJsonError carries .status, so classify_cloud_error above
            # correctly classifies this as 'auth' from the status code alone.
            # The leading message text also matters on its own: the hub's
            # completeJob() flips this node's cloud_auth_ok to 0 whenever it
            # sees the exact phrase "Ollama rejected the API key" (see
            # src/compute.js), the same wording the Android/iOS/JS workers
            # already use for this identical failure. resp_body is appended
            # because a bare status code alone is undiagnosable when a key
            # verifies as genuinely valid from elsewhere but keeps getting
            # rejected only from one machine/network - cf-ray in the headers
            # would confirm Cloudflare's edge blocked it before Ollama's own
            # auth check ever ran.
            cf_ray = e.headers.get("cf-ray") if getattr(e, "headers", None) else None
            suffix = " ".join(filter(None, [f"[cf-ray={cf_ray}]" if cf_ray else None, resp_body[:300] or None]))
            raise HttpJsonError(e.code, f"Ollama rejected the API key - invalid or revoked {suffix}".strip(), "https://ollama.com/api/chat") from e
        raise HttpJsonError(e.code, resp_body, "https://ollama.com/api/chat") from e
    message = result.get("message") or {}
    content = message.get("content") or message.get("thinking") or ""
    output_tokens = int(result.get("eval_count") or 0)
    return content, output_tokens


_CLOUD_QUOTA_PATTERN = re.compile(
    r"quota|rate.?limit|too many requests|insufficient.*(balance|credit)|credit.*(exhaust|insufficient)",
    re.I,
)
_CLOUD_AUTH_PATTERN = re.compile(
    r"unauthorized|not signed in|sign.?in required|authentication|invalid.*(token|api.?key)|forbidden",
    re.I,
)


def classify_cloud_error(err):
    """Distinguish a REAL Ollama Cloud rejection (429, or a 402/error body
    that actually talks about quota/credits) from an auth failure or an
    unrelated error (network blip, model missing, etc). Returns 'quota',
    'auth', or None. This is the only place that observes Ollama's actual
    enforcement - Ollama publishes no API for remaining balance, so this is
    the sole way to learn a real account's real ceiling (see
    docs/cloud-models.md)."""
    status = getattr(err, "status", None)
    body = getattr(err, "body", "") or str(err)
    if _CLOUD_AUTH_PATTERN.search(body) and status in (401, 403):
        return "auth"
    if status == 429:
        return "quota"
    if status == 402 and not _CLOUD_AUTH_PATTERN.search(body):
        return "quota"
    if _CLOUD_QUOTA_PATTERN.search(body):
        return "quota"
    if status in (401, 403) or _CLOUD_AUTH_PATTERN.search(body):
        return "auth"
    return None


def detect_gpu():
    try:
        out = _run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip().splitlines()[0]
    except Exception:
        pass
    try:
        out = _run(
            ["wmic", "path", "win32_VideoController", "get", "name"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in out.stdout.splitlines():
            line = line.strip()
            if line and "Name" not in line:
                return line
    except Exception:
        pass
    return None


def gpu_utilization():
    try:
        out = _run(
            ["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return float(out.stdout.strip().splitlines()[0])
    except Exception:
        pass
    return None


def local_models():
    try:
        resp = http_json(OLLAMA + "/api/tags", method="GET", timeout=10)
        return [m.get("name") for m in resp.get("models", [])]
    except Exception:
        return []


def local_model_sizes():
    try:
        resp = http_json(OLLAMA + "/api/tags", method="GET", timeout=10)
        return {
            m.get("name"): round((m.get("size") or 0) / 1048576, 1)
            for m in resp.get("models", [])
        }
    except Exception:
        return {}


def is_cloud_model(name):
    """Ollama cloud tags look like `kimi-k3:cloud` or `gpt-oss:20b-cloud`."""
    n = str(name or "").lower()
    return ":cloud" in n or n.endswith("-cloud")


# Non-Ollama cloud providers (Google AI Studio, Mistral AI Studio, ...) -
# mirrors src/externalProviders.js on the hub exactly (same provider ids,
# same URLs, same model-prefix routing) so a job dispatched there is
# executed here the same way. Both providers expose a genuine OpenAI-
# compatible chat-completions endpoint (confirmed against their own docs),
# so one generic caller (call_external_provider below) covers both - no
# provider-specific request/response parsing needed.
EXTERNAL_PROVIDERS = {
    "google": {"url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "prefix": re.compile(r"^gemini-", re.I)},
    "mistral": {"url": "https://api.mistral.ai/v1/chat/completions", "prefix": re.compile(r"^(mistral|codestral|pixtral|ministral)-", re.I)},
}


def detect_external_provider(model):
    name = str(model or "")
    for provider_id, info in EXTERNAL_PROVIDERS.items():
        if info["prefix"].search(name):
            return provider_id
    return None


def call_external_provider(provider_id, api_key, model, messages, max_tokens=None, timeout=120):
    """Generic OpenAI-compatible chat-completions call, shared by every
    provider in EXTERNAL_PROVIDERS - see the registry comment for why one
    implementation covers all of them."""
    url = EXTERNAL_PROVIDERS[provider_id]["url"]
    body = {"model": model, "messages": messages}
    if max_tokens:
        body["max_tokens"] = max_tokens
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "TokenBrokerWorker/1.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        resp_body = ""
        try:
            resp_body = e.read().decode(errors="replace")
        except Exception:
            pass
        if e.code in (401, 403):
            raise HttpJsonError(e.code, f"{provider_id} rejected the API key - {resp_body[:300]}", url) from e
        raise HttpJsonError(e.code, resp_body, url) from e
    choice = (result.get("choices") or [{}])[0]
    content = (choice.get("message") or {}).get("content") or ""
    usage = result.get("usage") or {}
    tokens = int(usage.get("completion_tokens") or usage.get("total_tokens") or 0)
    return content, tokens


def ollama_bin():
    """Locate the Ollama CLI (it is not always on PATH, especially Windows)."""
    if sys.platform.startswith("win"):
        for base in (
            os.environ.get("LOCALAPPDATA", ""),
            os.environ.get("ProgramFiles", ""),
            os.environ.get("ProgramFiles(x86)", ""),
        ):
            cand = os.path.join(base, "Programs", "Ollama", "ollama.exe")
            if cand and os.path.exists(cand):
                return cand
    try:
        from shutil import which

        return which("ollama")
    except Exception:
        return None


def ollama_account_from_signin(output):
    """Extract the signed-in ollama.com username from `ollama signin` output.

    Handles the formats seen across Ollama CLI versions:
      - already signed in as user 'name'
      - already signed in as 'name'
      - You are already signed in as name
      - signed in as 'name' / logged in as name
    """
    text = output or ""
    for pat in (
        r"already signed in as user ['\"]?([^'\"]+)",
        r"already signed in as ['\"]?([^'\"]+)",
        r"(?:signed|logged) in as (?:user )?['\"]?([^'\"]+?)['\"]?\s*$",
    ):
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            name = m.group(1).strip().rstrip(".'\"")
            if name:
                return name
    return None


CLOUD_LOCK = threading.Lock()


def cloud_state_path():
    """Persistent cloud-auth memory, stored next to worker-config.json so the
    worker remembers the signed-in ollama.com user across restarts/reboots."""
    return os.path.join(app_dir(), "worker-cloud.json")


def save_config_pref(key, value):
    """Persist a worker preference (e.g. private_jobs) back to worker-config.json."""
    try:
        path = os.path.join(app_dir(), "worker-config.json")
        with open(path, encoding="utf-8-sig") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            cfg = {}
        cfg[key] = value
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def load_cloud_state():
    """Restore the last verified ollama.com account + cloud toggle. Ollama's
    own session lives in the running Ollama server; this file lets the worker
    show the signed-in user immediately and re-verify on boot."""
    try:
        with open(cloud_state_path()) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return
        for key in (
            "account", "login", "auth_ok", "verified_at", "enabled", "subscription", "paywalled",
            "real_limit_hit", "real_limit_hit_at", "real_limit_hit_tokens", "real_limit_cleared_at",
        ):
            if key in data:
                STATE["cloud"][key] = data[key]
    except Exception:
        pass


def save_cloud_state():
    try:
        with open(cloud_state_path(), "w") as f:
            json.dump(
                {
                    "account": STATE["cloud"].get("account"),
                    "login": STATE["cloud"].get("login"),
                    "auth_ok": STATE["cloud"].get("auth_ok"),
                    "verified_at": STATE["cloud"].get("verified_at"),
                    "enabled": bool(STATE["cloud"].get("enabled")),
                    "subscription": STATE["cloud"].get("subscription"),
                    "paywalled": STATE["cloud"].get("paywalled") or [],
                    "real_limit_hit": STATE["cloud"].get("real_limit_hit"),
                    "real_limit_hit_at": STATE["cloud"].get("real_limit_hit_at"),
                    "real_limit_hit_tokens": STATE["cloud"].get("real_limit_hit_tokens"),
                    "real_limit_cleared_at": STATE["cloud"].get("real_limit_cleared_at"),
                },
                f,
                indent=2,
            )
    except Exception:
        pass


def pool_state_path():
    """Persistent on-demand-pull tracker. Only models the worker pulled itself
    are evicted when idle; models that were already local stay forever."""
    return os.path.join(app_dir(), "worker-pool.json")


def load_pool_state():
    try:
        with open(pool_state_path()) as f:
            data = json.load(f)
        if isinstance(data, dict):
            STATE["pool"] = data
    except Exception:
        pass


def save_pool_state():
    try:
        with open(pool_state_path(), "w") as f:
            json.dump(STATE.get("pool", {}), f, indent=2)
    except Exception:
        pass


def pool_touch(model):
    """Mark a model as system-pulled / just-used (for idle eviction)."""
    if not model:
        return
    now = time.time()
    pool = STATE.setdefault("pool", {})
    if model not in pool:
        pool[model] = {"pulled_at": now, "last_used_at": now, "size_mb": None}
    else:
        pool[model]["last_used_at"] = now
    save_pool_state()


def pool_size_mb():
    return sum(float(i.get("size_mb") or 0) for i in STATE.get("pool", {}).values())


def models_dir():
    return os.environ.get("OLLAMA_MODELS") or os.path.join(
        os.path.expanduser("~"), ".ollama", "models"
    )


def free_storage_gb():
    """Actual free space on the Ollama models drive (GB)."""
    try:
        import shutil

        return shutil.disk_usage(models_dir()).free / (1024 ** 3)
    except Exception:
        return 0.0


def _remove_model(model):
    """Remove a pool model locally. Returns True when it is gone."""
    bin_path = ollama_bin()
    if not bin_path:
        return False
    try:
        proc = _run([bin_path, "rm", model], capture_output=True, text=True, timeout=120)
        text = ((proc.stdout or "") + (proc.stderr or "")).lower()
        if proc.returncode == 0 or "not found" in text:
            STATE["pool"].pop(model, None)
            return True
        # Failed to remove (e.g. model in use) - retry on the next sweep.
        STATE["pool"][model]["last_used_at"] = time.time()
    except Exception:
        pass
    return False


def evict_for_space(required_gb, margin_gb=1.0):
    """Evict idle pool models (oldest first) until >= required_gb is free.
    Returns True when the target free space is available. Cloud manifests are
    tiny and never evicted."""
    target = float(required_gb) + float(margin_gb)
    if free_storage_gb() >= target:
        return True
    ordered = sorted(
        (
            (name, info.get("last_used_at") or info.get("pulled_at") or 0)
            for name, info in STATE.get("pool", {}).items()
            if not is_cloud_model(name)
        ),
        key=lambda x: x[1],
    )
    removed = 0
    for name, _ in ordered:
        if free_storage_gb() >= target:
            break
        if _remove_model(name):
            removed += 1
    if removed:
        save_pool_state()
        print(f"disk pressure: evicted {removed} pool model(s)")
        STATE["pool_evictions"] = int(STATE.get("pool_evictions") or 0) + removed
    return free_storage_gb() >= target


def _after_job_cleanup(model):
    """Ephemeral compute: after a job finishes, unload the model from VRAM and
    remove it from disk (even cloud manifests) so the node never accumulates
    models. Models the user already had locally (not pulled by the worker for
    a job) are never touched - they are not pool-tracked."""
    if not model:
        return
    try:
        # Unload from VRAM: keep_alive 0 with an empty prompt releases the
        # loaded model immediately.
        http_json(OLLAMA + "/api/generate", {"model": model, "keep_alive": 0}, timeout=30)
    except Exception:
        pass
    if model in STATE.get("pool", {}):
        if _remove_model(model):
            save_pool_state()
            try:
                STATE["models"] = local_models()
            except Exception:
                pass


def evict_idle_pool(max_idle_hours):
    """Remove system-pulled models unused for more than max_idle_hours so a
    node never accumulates disk usage. Cloud manifests are tiny and are the
    whole point of the node, so they are never evicted; models that were
    already local before the worker are not tracked and never evicted."""
    if not max_idle_hours or max_idle_hours <= 0:
        return 0
    cutoff = time.time() - float(max_idle_hours) * 3600
    removed = []
    for model, info in list(STATE.get("pool", {}).items()):
        if is_cloud_model(model):
            continue
        last = info.get("last_used_at") or info.get("pulled_at") or 0
        if last >= cutoff:
            continue
        if _remove_model(model):
            removed.append(model)
    if removed:
        save_pool_state()
        print(f"evicted idle pool model(s): {', '.join(removed)}")
        STATE["pool_evictions"] = int(STATE.get("pool_evictions") or 0) + len(removed)
    return len(removed)


def verify_cloud_account():
    """Non-interactive ollama.com session check. `ollama signin` prints
    "already signed in as user 'X'" and exits immediately when the session is
    valid; when signed out it waits for a browser flow, so a timeout means
    signed out. Older Ollama builds use `login` instead of `signin`, so we
    fall back before declaring the session lapsed. Ambiguous check failures
    (timeout, unrecognized output) never hard-flip a previously-good session
    to 'signed out' - they mark auth as unknown so a later re-verify can
    restore it without a manual sign-in."""
    with CLOUD_LOCK:
        confirmed = False
        acct = None
        bin_path = ollama_bin()
        for cmd in ("signin", "login"):
            if not bin_path:
                break
            try:
                proc = _run([bin_path, cmd], capture_output=True, text=True, timeout=20)
                output = (proc.stdout or "") + (proc.stderr or "")
                parsed = ollama_account_from_signin(output)
                if proc.returncode == 0 and parsed:
                    confirmed = True
                    acct = parsed
                    break
            except Exception:
                continue
        if confirmed and acct:
            STATE["cloud"]["account"] = acct
            STATE["cloud"]["login"] = True
            STATE["cloud"]["auth_ok"] = True
            STATE["cloud"]["verified_at"] = time.time()
            save_cloud_state()
            return
        # Couldn't confirm the session. If it was previously good, keep the
        # account and mark auth unknown (not signed out) so the next re-verify
        # restores it; only a definitive failure flips login to False.
        was_ok = STATE["cloud"].get("auth_ok") is True
        if not bin_path:
            was_ok = False
        STATE["cloud"]["auth_ok"] = None if was_ok else False
        if not was_ok:
            STATE["cloud"]["login"] = False
        STATE["cloud"]["verified_at"] = time.time()
        save_cloud_state()


def refresh_cloud_account():
    """After a cloud job, re-verify (and persist) the ollama.com account."""
    verify_cloud_account()


# --- BigMoeOnEdge runtime (optional) ---------------------------------------
# Lets a small machine serve Mixture-of-Experts models far bigger than its RAM
# by streaming the experts each token needs from flash (github.com/Helldez/
# BigMoeOnEdge, Apache-2.0, built on llama.cpp). It has no HTTP server: its
# long-running mode is `bmoe-cli --session`, a JSON-lines protocol over
# stdin/stdout. Models are public names starting with "bmoe-" and are mapped to
# local GGUF files in worker-config.json ("bigmoe": {...}); the hub only
# dispatches one to a node that advertises that exact name.
BMOE_PREFIX = "bmoe-"
BMOE_CREATE_NO_WINDOW = 0x08000000


def is_bigmoe_model(name):
    return str(name or "").lower().startswith(BMOE_PREFIX)


def _bmoe_find_exe(cfg):
    exe = cfg.get("exe")
    if exe and os.path.isfile(exe):
        return exe
    base = cfg.get("dir") or os.environ.get("BIGMOE_DIR")
    if not base:
        return None
    for sub_dir in ("", os.path.join("build", "cli", "Release"), os.path.join("build", "cli"), "bin"):
        for n in ("bmoe-cli.exe", "bmoe-cli"):
            cand = os.path.join(base, sub_dir, n)
            if os.path.isfile(cand):
                return cand
    return None


def configure_bigmoe(cfg):
    """Validate the optional "bigmoe" config block and record what this node
    can actually serve (engine found AND the GGUF present)."""
    st = {"enabled": False, "models": {}}
    STATE["bigmoe"] = st
    if not isinstance(cfg, dict) or not cfg.get("enabled", True) or not cfg.get("models"):
        return
    exe = _bmoe_find_exe(cfg)
    if not exe:
        print("bigmoe: bmoe-cli not found (set bigmoe.exe or bigmoe.dir) - disabled")
        return
    models = {}
    for name, path in (cfg.get("models") or {}).items():
        if not is_bigmoe_model(name):
            print(f"bigmoe: model name '{name}' must start with '{BMOE_PREFIX}' - skipped")
        elif not os.path.isfile(str(path)):
            print(f"bigmoe: GGUF for '{name}' not found at {path} - skipped")
        else:
            models[name] = str(path)
    if not models:
        return
    cores = os.cpu_count() or 4
    dll_dir = cfg.get("dll_dir")
    if not dll_dir:
        dll_dir = os.path.join(cfg["dir"], "build", "bin", "Release") if cfg.get("dir") else os.path.dirname(exe)
    st.update(
        enabled=True,
        exe=exe,
        models=models,
        dll_dir=dll_dir,
        threads=int(cfg.get("threads") or max(2, cores // 2)),
        ctx=int(cfg.get("ctx") or 4096),
        cache_ceil_mb=int(cfg.get("cache_ceil_mb") or 3000),
        cache_floor_mb=int(cfg.get("cache_floor_mb") or 2048),
        io_threads=int(cfg.get("io_threads") or 4),
        idle_unload_s=float(cfg.get("idle_unload_s") or 300),
        extra_args=[str(a) for a in (cfg.get("extra_args") or [])],
    )
    print(f"bigmoe: enabled, serving {', '.join(models)} via {exe}")


class BigMoeSession:
    """One persistent `bmoe-cli --session` process (one model). Requests are
    serialised - it is a single CPU/IO-bound engine."""

    def __init__(self, model_name, model_path, opts):
        self.model_name = model_name
        self.model_path = model_path
        self.opts = opts
        self.proc = None
        self.ready = {}
        self.pending = {}
        self.cv = threading.Condition()
        self.next_id = 1
        self.last_used = time.time()

    def is_up(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self, timeout=180.0):
        o = self.opts
        args = [
            o["exe"], "-m", self.model_path, "--session", "--moe-stream",
            "--cache-mb", "auto", "--cache-floor-mb", str(o["cache_floor_mb"]),
            "--cache-ceil-mb", str(o["cache_ceil_mb"]), "--io-threads", str(o["io_threads"]),
            "-t", str(o["threads"]), "-c", str(o["ctx"]), "--chatml",
        ] + list(o.get("extra_args") or [])
        env = dict(os.environ)
        if sys.platform.startswith("win"):
            env["PATH"] = o["dll_dir"] + os.pathsep + env.get("PATH", "")
        else:
            env["LD_LIBRARY_PATH"] = o["dll_dir"] + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        kw = {}
        if sys.platform.startswith("win"):
            kw["creationflags"] = BMOE_CREATE_NO_WINDOW
        self.proc = subprocess.Popen(
            args, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace", bufsize=1, **kw,
        )
        threading.Thread(target=self._read_loop, args=(self.proc,), daemon=True, name="bigmoe-reader").start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.ready:
                self.last_used = time.time()
                return self.ready
            if self.proc.poll() is not None:
                raise RuntimeError("bmoe-cli exited before the model finished loading")
            time.sleep(0.2)
        self.stop()
        raise RuntimeError("timed out loading the model")

    def _read_loop(self, proc):
        for raw in proc.stdout:
            line = raw.strip()
            if not line.startswith("BMOE_"):
                continue
            tag, _, rest = line.partition(" ")
            try:
                data = json.loads(rest) if rest else {}
            except ValueError:
                data = {}
            if tag == "BMOE_READY":
                self.ready = data or {"ok": True}
            elif tag in ("BMOE_DONE", "BMOE_ERROR"):
                with self.cv:
                    self.pending[data.get("id", 0)] = {"tag": tag, **data}
                    self.cv.notify_all()
        with self.cv:
            self.cv.notify_all()

    @staticmethod
    def _send_to(proc, obj):
        proc.stdin.write(json.dumps(obj, separators=(",", ":")) + "\n")
        proc.stdin.flush()

    def generate(self, prompt, n_predict, timeout):
        rid = self.next_id
        self.next_id += 1
        self._send_to(self.proc, {
            "cmd": "generate", "id": rid, "prompt": prompt,
            "n_predict": int(n_predict), "think": False, "clear_kv": True,
        })
        deadline = time.time() + timeout
        with self.cv:
            while rid not in self.pending:
                if time.time() >= deadline or not self.is_up():
                    break
                self.cv.wait(timeout=1.0)
            res = self.pending.pop(rid, None)
        if res is None:
            try:
                self._send_to(self.proc, {"cmd": "cancel"})
            except Exception:
                pass
            raise RuntimeError("bigmoe generation timed out" if self.is_up() else "bigmoe engine exited mid-job")
        self.last_used = time.time()
        if res["tag"] == "BMOE_ERROR":
            raise RuntimeError(f"bigmoe error: {res.get('msg', 'unknown')}")
        return res

    def stop(self):
        proc, self.proc = self.proc, None
        if not proc:
            return
        try:
            if proc.stdin and not proc.stdin.closed:
                self._send_to(proc, {"cmd": "close"})
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


_BMOE_SESSION = None


def bigmoe_models():
    st = STATE.get("bigmoe") or {}
    return list((st.get("models") or {}).keys()) if st.get("enabled") else []


def bigmoe_idle_sweep():
    """Release the engine's RAM/cache once nobody has used it for a while."""
    global _BMOE_SESSION
    st = STATE.get("bigmoe") or {}
    if _BMOE_SESSION and st.get("enabled") and time.time() - _BMOE_SESSION.last_used > st.get("idle_unload_s", 300):
        _BMOE_SESSION.stop()
        _BMOE_SESSION = None


def bigmoe_render_prompt(messages):
    """bmoe-cli's session takes one user prompt (it applies the chat template),
    so system text and earlier turns are folded into that single message."""
    sys_parts, turns = [], []
    for m in messages or []:
        c = m.get("content")
        if isinstance(c, list):
            c = " ".join(p.get("text", "") for p in c if isinstance(p, dict))
        c = str(c or "")
        if m.get("role") == "system":
            sys_parts.append(c)
        else:
            turns.append((m.get("role") or "user", c))
    if not turns:
        turns = [("user", "Hello")]
    if len(turns) == 1 and not sys_parts:
        return turns[0][1]
    out = []
    if sys_parts:
        out.append("Instructions:\n" + "\n".join(sys_parts))
    if len(turns) > 1:
        out.append("Conversation so far:")
        for role, c in turns[:-1]:
            out.append(("User: " if role == "user" else "Assistant: ") + c)
        out.append("Latest message from the user:")
    out.append(turns[-1][1])
    return "\n\n".join(out)


def run_bigmoe_job(job):
    global _BMOE_SESSION
    st = STATE.get("bigmoe") or {}
    model = job["model"]
    if job.get("kind", "chat") != "chat":
        raise ValueError("bigmoe models only serve chat jobs")
    path = (st.get("models") or {}).get(model) if st.get("enabled") else None
    if not path:
        raise RuntimeError(f"model {model} is not installed on this node")
    payload = job.get("payload") or {}
    prompt = bigmoe_render_prompt(payload.get("messages"))
    n_predict = max(16, min(int(payload.get("max_tokens") or 512), 2048))
    # Fixed context: the engine rejects prompt + generation past n_ctx, so
    # shrink the generation budget instead of failing a long-ish prompt.
    n_predict = min(n_predict, st["ctx"] - (len(prompt) // 3 + 32))
    if n_predict < 16:
        raise RuntimeError("prompt too long for this node's context window")
    if _BMOE_SESSION and (not _BMOE_SESSION.is_up() or _BMOE_SESSION.model_name != model):
        _BMOE_SESSION.stop()
        _BMOE_SESSION = None
    if not _BMOE_SESSION:
        STATE["job_state"] = "loading model"
        sess = BigMoeSession(model, path, st)
        sess.start()
        _BMOE_SESSION = sess
        STATE["job_state"] = "working"
    res = _BMOE_SESSION.generate(prompt, n_predict, timeout=min(1800, 120 + n_predict * 2))
    text = res.get("text") or ""
    print(
        f"bigmoe: {res.get('tokens')} tokens @ {res.get('tok_s')} tok/s, "
        f"prefill {res.get('prefill_s')}s, cache hit {res.get('cache_hit_pct')}%"
    )
    if not text.strip():
        raise RuntimeError("bigmoe produced no output")
    return {"response": text, "output_tokens": int(res.get("tokens") or 0)}


def advertised_models(cloud_enabled, exhausted=False):
    """Models this worker will accept. Cloud-gated models are only offered
    when the worker has Ollama Cloud enabled, the ollama.com session is
    verified (auth_ok True), AND quota remains; an exhausted or signed-out
    node stops advertising cloud models entirely so the hub never assigns a
    cloud job it cannot run."""
    paywalled = set(STATE["cloud"].get("paywalled") or [])
    models = [m for m in local_models() if m not in paywalled]
    auth_ok = STATE["cloud"].get("auth_ok") is True
    if not (cloud_enabled and auth_ok and not exhausted):
        models = [m for m in models if not is_cloud_model(m)]
    return models + [m for m in bigmoe_models() if m not in models]


def hiro_module():
    hiro_path = os.environ.get(
        "HIRO_PATH",
        r"C:\Users\b0052\Desktop\python projects\Projects\hiroglyph",
    )
    sys.path.insert(0, hiro_path)
    from hiro import HieroglyphicEncoder  # noqa: F401

    return HieroglyphicEncoder()


def hiro_encode(text, key):
    enc = hiro_module()
    with _silence_stdout():
        result = enc.encode_message(str(text), str(key), "aes")
    return result["hieroglyphics"]


def hiro_decode(glyph, key):
    enc = hiro_module()
    with _silence_stdout():
        result = enc.decode_message(str(glyph), str(key), "aes")
    return result.get("message") or result.get("text") or ""


def _silence_stdout():
    """Hiro prints the decoded message to stdout - suppress it so private
    payloads never become viewable on the worker."""
    import contextlib
    import io

    stack = contextlib.ExitStack()
    if sys.stdout is not None:
        sys.stdout.flush()
    if sys.stderr is not None:
        sys.stderr.flush()
    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
    return stack


def redact(text, keep=60):
    s = str(text or "")
    if len(s) <= keep:
        return s
    return s[:keep] + "..." + " (redacted)"


def job_preview(job):
    payload = job.get("payload") or {}
    if job.get("kind") == "chat":
        messages = payload.get("messages") or []
        for m in reversed(messages):
            if m.get("content"):
                return redact(m["content"])
        return "(no message content)"
    if job.get("kind") == "completions":
        return redact(payload.get("prompt"))
    if job.get("kind") == "embeddings":
        return redact(payload.get("input"))
    return "(unknown job)"


def run_job(job):
    if STATE.get("dry_run"):
        # Sleep past the duration quality gate, then return a varied answer so
        # the hub's anti-exploit checks (min duration, throughput, diversity)
        # accept the dry-run completion.
        time.sleep(3.5)
        return {"response": "Dry-run private job response from the real TokenBroker worker. The hub encoded the prompt as a glyph, the worker decoded it in memory, produced this answer, and returned an encoded glyph. Everything completed end to end without touching disk.", "output_tokens": 200}
    model = job["model"]
    kind = job.get("kind", "chat")
    payload = job.get("payload") or {}
    if is_bigmoe_model(model):
        return run_bigmoe_job(job)
    # Non-Ollama cloud providers (Google AI Studio, Mistral AI Studio, ...) -
    # these never run locally at all (unlike Ollama cloud models, which can
    # at least be attempted through the local proxy), so the ONLY path is
    # this direct call using a synced-down key. The hub only ever dispatches
    # one of these here when it already confirmed this account holds a key
    # for that exact provider (see jobTier in src/compute.js), so a missing
    # key at this point would mean the key was removed after the job was
    # already assigned - rare, but handled below rather than assumed away.
    external_provider = detect_external_provider(model) if kind == "chat" else None
    if external_provider:
        api_key = STATE["provider_keys"].get(external_provider)
        if not api_key:
            raise RuntimeError(f"no {external_provider} API key configured on this worker")
        content, output_tokens = call_external_provider(
            external_provider,
            api_key,
            model,
            payload.get("messages") or [{"role": "user", "content": "Hello"}],
            max_tokens=payload.get("max_tokens"),
        )
        return {"response": content, "output_tokens": output_tokens}
    # Fallback path: a cloud-tagged job on a machine with no working local
    # `ollama signin` session, but a key synced down from the hub (account-
    # wide, set on the Compute tab, or per-node). The normal local-proxy path
    # below is preferred whenever signin already works, since it needs no key
    # at all - this only ever activates as a substitute for a real signin.
    if (
        kind == "chat"
        and is_cloud_model(model)
        and STATE["cloud"].get("auth_ok") is not True
        and STATE["cloud"].get("api_key")
    ):
        content, output_tokens = call_ollama_cloud_direct(
            STATE["cloud"]["api_key"],
            model,
            payload.get("messages") or [{"role": "user", "content": "Hello"}],
            max_tokens=payload.get("max_tokens"),
        )
        # Flagged so the caller doesn't infer "local signin must be working"
        # from this success (see the auth_ok=True line after a cloud job
        # completes) - that would wrongly switch future jobs back to the
        # local proxy path, which still isn't actually signed in.
        return {"response": content, "output_tokens": output_tokens, "cloud_via_direct_key": True}
    if kind == "chat":
        body = {
            "model": model,
            "messages": payload.get("messages") or [{"role": "user", "content": "Hello"}],
            "stream": False,
        }
        if payload.get("max_tokens"):
            body["max_tokens"] = payload["max_tokens"]
        url = OLLAMA + "/v1/chat/completions"
        # Reasoning models (gpt-oss, DeepSeek-R1, Kimi, GLM, Qwen thinking)
        # put their chain-of-thought in `message.reasoning` and can leave
        # `content` null. Fall back to reasoning so the hub never gets an
        # empty response for a job the node actually completed.
        content_key = lambda res: (  # noqa: E731
            res["choices"][0]["message"].get("content")
            or res["choices"][0]["message"].get("reasoning")
            or ""
        )
    elif kind == "completions":
        body = {"model": model, "prompt": payload.get("prompt", ""), "stream": False}
        url = OLLAMA + "/v1/completions"
        content_key = lambda res: res["choices"][0]["text"]  # noqa: E731
    elif kind == "embeddings":
        body = {"model": model, "input": payload.get("input", "")}
        url = OLLAMA + "/v1/embeddings"
        content_key = lambda res: {"embedding": res["data"][0]["embedding"]}  # noqa: E731
    else:
        raise ValueError(f"unknown job kind: {kind}")

    result = http_json(url, body, timeout=600)
    content = content_key(result)
    usage = result.get("usage") or {}
    output_tokens = usage.get("completion_tokens") or usage.get("total_tokens") or 0
    # The response is returned to the hub in memory. It is never logged,
    # written to disk, or shown in the stats window.
    return {
        "response": content if isinstance(content, str) else json.dumps(content),
        "output_tokens": int(output_tokens),
    }


def sample_cpu(last):
    now = time.time()
    try:
        cpu_times = os.times()
        used = cpu_times.user + cpu_times.system - last["used"]
        delta = now - last["at"]
        last["used"] += used
        last["at"] = now
        if delta > 0:
            return min(100.0, max(0.0, used / delta * 100.0))
    except Exception:
        pass
    return 0.0


def write_pid_file():
    try:
        pid_dir = app_dir()
        with open(os.path.join(pid_dir, "worker.pid"), "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass


def _pid_alive(pid):
    try:
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return exit_code.value == 259  # STILL_ACTIVE
    except Exception:
        return False


def another_instance_running():
    """A second worker would fight over the stats port and pid file - exit."""
    pid_file = os.path.join(app_dir(), "worker.pid")
    try:
        if os.path.exists(pid_file):
            with open(pid_file) as f:
                old = f.read().strip()
            if old.isdigit() and _pid_alive(old):
                return True
    except Exception:
        pass
    return False


def worker_self_hash():
    """SHA-256 of the running binary (exe when frozen) for tamper evidence."""
    try:
        # Glyph-runner mode: the hub served the source this process is running
        # from, so report that hash (set by the runner before exec) instead of
        # the bootstrap exe's hash - the hub binds the node to the source.
        # Only trust the source-hash override when the trusted glyph runner
        # (served by the hub) set both markers; a normal exe run never accepts
        # an environment-supplied hash, so local tampering cannot spoof it.
        override = os.environ.get("TOKENBROKER_SOURCE_HASH")
        if override and os.environ.get("TOKENBROKER_RUNNER") == "1":
            return override
        target = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
        h = hashlib.sha256()
        with open(target, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class StatsHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the console quiet
        pass

    def _send(self, code, body, content_type):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        provided = query.get("token", [None])[0]
        cookie_token = None
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if part.startswith("tb_stats="):
                cookie_token = part.split("=", 1)[1]
        token = provided or cookie_token
        if not token or not hmac.compare_digest(token, STATS_TOKEN):
            self._send(401, "unauthorized", "text/plain")
            return
        path = urlparse(self.path).path
        if path == "/" and provided:
            # Swap the ?token= URL for a local cookie so the token never
            # lingers in the address bar, history, or screenshots.
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", f"tb_stats={STATS_TOKEN}; Path=/; HttpOnly; SameSite=Strict")
            self.end_headers()
            return
        self.path = path
        if self.path == "/api/stats":
            self._send(200, json.dumps(STATE), "application/json")
            return
        html = """<!doctype html><html><head><meta charset="utf-8">
<title>TokenBroker Worker</title>
<style>
body{font-family:system-ui,Segoe UI,sans-serif;margin:0;background:#0f1115;color:#e5e7eb;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#9ca3af;font-size:13px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px}
.card{background:#161922;border:1px solid #262b36;border-radius:10px;padding:14px}
.label{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af}
.value{font-size:20px;margin-top:4px;font-variant-numeric:tabular-nums}
.job{background:#161922;border:1px solid #262b36;border-radius:10px;padding:14px;margin-bottom:10px}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#9ca3af}
.ok{color:#34d399}.warn{color:#fbbf24}
</style></head><body>
<h1>TokenBroker Worker</h1>
<div class="sub">Opaque compute node - prompts and outputs stay hidden. This window shows health and earnings only.</div>
<div class="sub" style="max-width:780px;line-height:1.5">Cloud models require a free ollama.com account. Sign in
with the worker's "Sign in" button (or run: ollama signin) - your account plan sets the quota: Free = light usage,
1 cloud model at a time; Pro ($20/mo) = 50x usage, 3 at a time; Max ($100/mo) = 5x Pro, 10 at a time. Session
limits reset every 5 hours, weekly limits every 7 days. Ollama does not expose remaining quota through its API, so
the cloud numbers here are this node's hourly budget (set by TokenBroker). See ollama.com/settings/usage for your
account's real usage.</div>
<div class="grid" id="grid"></div>
<div id="jobs"></div>
<script>
async function load(){try{
 const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const q=new URLSearchParams(location.search);
 const T=q.get('token')||'';
 const s=await (await fetch('/api/stats'+(T?'?token='+T:''),{credentials:'include'})).json();
 const g=document.getElementById('grid');
 const vm=s.vm||{score:0,reasons:[]};
 g.innerHTML=[
  ['Status',esc(s.status)],['Gateway',esc(s.gateway||'-')],['GPU',esc(s.gpu||'CPU only')],
  ['CPU',s.cpu_pct.toFixed(1)+'%'],['Uptime',Math.floor(s.uptime_s/60)+'m'],
  ['Heartbeats',s.heartbeats],['Jobs completed',s.jobs_completed],['Jobs failed',s.jobs_failed],
  ['Tokens',s.tokens],['Credits',(s.credits||0)+' '+(s.credits_tier||'')],
  ['Ollama account',s.private_mode?'hidden (private mode)':esc((s.cloud&&s.cloud.login)?(s.cloud.account||'signed in'):(s.cloud&&s.cloud.auth_ok===false?'signed out':'not signed in'))],
  ['Models',esc((s.models||[]).join(', ')||'-')],['Last heartbeat',esc(s.last_heartbeat_at||'-')],
 ['Fingerprint',esc((s.fingerprint||'-').slice(0,12)+'...')],
 ['VM check',vm.score>0.5?'SUSPICIOUS ('+vm.score+')':('clean ('+vm.score+')')],
 ['Build',s.worker_verified===true?'verified':(s.worker_verified===false?'MODIFIED':'n/a')],
 ['Worker hash',esc((s.worker_hash||'-').slice(0,12)+'...')],
  ['Quality',esc((s.quality&&s.quality.tier)||'-')],
  ['Expected speed',(s.quality? (s.quality.tps+' tok/s') : '-')],
  ['Est. daily credits',(s.quality&&s.quality.daily_credits!=null)? (s.quality.daily_credits+' credits/day') : '-']
  ,['Pool',esc((s.pool_count||0)+' models / '+(s.pool_mb||0)+' MB - evict idle >'+(s.max_pool_idle_hours||2)+'h')]
 ].map(([l,v])=>`<div class="card"><div class="label">${l}</div><div class="value">${v}</div></div>`).join('');
 const j=s.last_job;
 document.getElementById('jobs').innerHTML=j?`<div class="job">
   <div><b>Last job</b> <span class="mono">${esc(j.id)} - ${esc(j.model)} (${esc(j.kind)})</span></div>
   <div class="mono" style="margin-top:6px">Redacted prompt: ${esc(j.redacted_prompt)}</div>
   <div class="mono">Started ${esc(j.started_at)} - finished ${esc(j.finished_at)} (${Number(j.latency_ms)||0}ms)</div>
   <div class="mono">Output tokens: ${Number(j.tokens)||0} - this job's credit: ${Number(j.credits)||0} ${esc(j.credit_tier||'')}</div>
 </div>`:'<div class="card"><div class="label">Waiting for jobs</div></div>';
}catch(e){document.getElementById('jobs').innerHTML='<div class="card warn">'+esc(e)+'</div>'}}
load();setInterval(load,2000);
</script></body></html>"""
        self._send(200, html, "text/html; charset=utf-8")


def start_stats_server():
    """Bind the stats server, falling back to the next ports if taken."""
    last_err = None
    for port in range(STATS_PORT, STATS_PORT + 10):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), StatsHandler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            return server, port
        except OSError as err:
            last_err = err
    raise last_err


def worker_loop(gateway, token, interval, hw_payload, private_jobs=True):
    """Heartbeat / claim / run / report loop, driven in a background thread."""
    cpu_state = {"used": 0.0, "at": time.time()}
    completion_times = []
    cloud_usage = []
    cloud_last_verify = time.time()
    disk_last_check = time.time()
    pool_last_sweep = time.time()
    while not STOP_EVENT.is_set():
        cloud_enabled = STATE["cloud"].get("enabled", False)
        STATE["uptime_s"] = int(time.time() - STATE["started_at"])
        STATE["cpu_pct"] = sample_cpu(cpu_state)
        STATE["gpu_util"] = gpu_utilization()
        now = time.time()
        completion_times = [t for t in completion_times if t > now - 60]
        STATE["rpm"] = len(completion_times)
        cloud_usage = [u for u in cloud_usage if u[0] > now - 3600]
        cloud_used = sum(t for _, t in cloud_usage)
        STATE["cloud"]["used_tokens_per_hour"] = cloud_used
        STATE["cloud"]["remaining"] = max(
            0, int(STATE["cloud"].get("quota_per_hour", 0)) - cloud_used
        )
        cloud_exhausted = bool(
            STATE["cloud"].get("enabled", False)
            and (
                (STATE["cloud"].get("remaining", 0) <= 0 and cloud_used > 0)
                or cloud_real_limit_active()
            )
        )
        # Re-verify the ollama.com session every 10 minutes so a lapsed login
        # is detected promptly and cloud models stop being advertised (and
        # resume as soon as the user signs back in).
        if time.time() - cloud_last_verify > 600:
            cloud_last_verify = time.time()
            threading.Thread(target=verify_cloud_account, daemon=True).start()
        # Idle-pool eviction sweep: drop system-pulled models unused for more
        # than max_pool_idle_hours so a node never accumulates disk usage.
        bigmoe_idle_sweep()
        if time.time() - pool_last_sweep > 300:
            pool_last_sweep = time.time()
            evict_idle_pool(STATE.get("max_pool_idle_hours", 2))
        # Disk-pressure safety: if the drive drops below 5 GB free, evict idle
        # pool models (oldest first) until ~8 GB is available. A full disk
        # stalls even cloud manifest pulls.
        if time.time() - disk_last_check > 60:
            disk_last_check = time.time()
            if free_storage_gb() < 5.0:
                evict_for_space(8.0)
        STATE["pool_count"] = len(STATE.get("pool", {}))
        STATE["pool_mb"] = round(pool_size_mb(), 1)
        STATE["history"] = (STATE["history"] + [
            {
                "t": time.strftime("%H:%M"),
                "rpm": STATE["rpm"],
                "online": STATE["status"] == "online",
                "tokens": STATE["tokens"] - STATE.get("_last_tokens", 0),
            }
        ])[-40:]
        STATE["_last_tokens"] = STATE["tokens"]

        if PAUSE_EVENT.is_set():
            STATE["job_state"] = "paused"
            time.sleep(2)
            continue

        try:
            offered = advertised_models(cloud_enabled, cloud_exhausted)
            hb = http_json(
                f"{gateway}/api/compute/heartbeat",
                {
                    "token": token,
                    "gpu": STATE["gpu"],
                    "models": offered,
                    "base_url": None,
                    "fingerprint": STATE["fingerprint"],
                    "vm": STATE["vm"],
                    "hw": hw_payload,
                    "worker_hash": STATE["worker_hash"],
                    "cloud": STATE["cloud"],
                    # Report real free space (capped at the configured budget)
                    # so the hub never assigns a pull the disk cannot hold.
                    "storage_gb": round(min(STATE["storage_gb"], free_storage_gb()), 1),
                    "private_jobs": STATE.get("private_jobs", True),
                },
                timeout=30,
            )
            STATE["status"] = hb.get("node", {}).get("status") or "online"
            STATE["heartbeats"] += 1
            STATE["last_heartbeat_at"] = time.strftime("%H:%M:%S")
            STATE["quality"] = {
                "tier": hb.get("node", {}).get("quality_tier"),
                "tps": hb.get("node", {}).get("expected_tps"),
                "daily_credits": hb.get("node", {}).get("expected_daily_credits"),
            }
            registered = hb.get("node", {}).get("worker_hash")
            if registered:
                STATE["worker_verified"] = registered == STATE["worker_hash"]
            else:
                STATE["worker_verified"] = None
            # A key set on the dashboard (account-wide, or per-node) rides
            # back on this node's own heartbeat response - the same
            # sync-down path the mobile/Android/iOS workers already use.
            # Only ever CONSUMED as a fallback (see run_job) when this
            # machine's own `ollama signin` isn't authenticated; never
            # required or used when local signin already works.
            synced_key = hb.get("node", {}).get("cloud_api_key")
            if synced_key:
                STATE["cloud"]["api_key"] = synced_key
            # Non-Ollama provider keys (Google AI Studio, Mistral AI Studio,
            # ...) - a plain top-level field on the heartbeat response
            # (unlike cloud_api_key, which lives under "node" for historical
            # reasons), always present as an object (possibly empty) so
            # "checked, nothing configured" is distinguishable from a
            # response that omitted the field entirely.
            if isinstance(hb.get("provider_keys"), dict):
                STATE["provider_keys"] = hb["provider_keys"]
            STATE["job_state"] = "idle"
            print(f"[{time.strftime('%H:%M:%S')}] heartbeat ok")
        except Exception as err:
            STATE["status"] = "gateway unreachable"
            STATE["job_state"] = "offline"
            STATE["last_error"] = str(err)
            print(f"[{time.strftime('%H:%M:%S')}] heartbeat failed: {err}")
            time.sleep(interval)
            continue

        try:
            claim = http_json(
                f"{gateway}/api/compute/jobs/claim",
                {
                    "token": token,
                    "models": advertised_models(cloud_enabled, cloud_exhausted),
                    "visibility": "all" if STATE.get("private_jobs", private_jobs) else "pub",
                },
                timeout=30,
            )
        except Exception as err:
            STATE["last_error"] = str(err)
            time.sleep(interval)
            continue

        job = claim.get("job")
        if not job:
            STATE["job_state"] = "idle"
            time.sleep(interval)
            continue

        # Private jobs are opaque: while one is in flight (and until a public
        # job replaces it), the stats window hides the operator's Ollama
        # account name so identity is not tied to private work.
        STATE["private_mode"] = job.get("visibility") == "priv"

        # On-demand pulls: the hub can assign a catalog model this node does
        # not have yet (it only does so when the node has disk space for it).
        # Cloud models pull almost instantly; local models take a while.
        # External-provider models (Google AI Studio, Mistral AI Studio, ...)
        # never exist in `ollama list` and never will - they're served over
        # HTTP with a synced-down API key (see run_job's external_provider
        # branch), so `ollama pull` would always fail for them and must
        # never be attempted.
        if (
            job.get("model") not in STATE["models"]
            and not STATE.get("dry_run")
            and not detect_external_provider(job.get("model"))
            and not is_bigmoe_model(job.get("model"))
        ):
            STATE["job_state"] = "pulling"
            STATE["current_job"] = job["model"]
            STATE["last_error"] = f"Pulling model {job['model']}..."
            print(f"pulling model {job['model']}...")
            bin_path = ollama_bin()
            if not bin_path:
                try:
                    http_json(
                        f"{gateway}/api/compute/jobs/{job['id']}/complete",
                        {"token": token, "error": "Ollama CLI not found - cannot pull model"},
                        timeout=30,
                    )
                except Exception:
                    pass
                time.sleep(1)
                continue
            try:
                # Make room first: a full disk stalls even cloud manifest
                # pulls. Evict idle pool models until there is headroom.
                evict_for_space(2.0)
                proc = _run(
                    [bin_path, "pull", job["model"]],
                    capture_output=True,
                    text=True,
                    timeout=1800,
                )
                if proc.returncode != 0:
                    raise RuntimeError((proc.stdout or proc.stderr or "")[-300:])
                STATE["models"] = local_models()
                pool_touch(job["model"])
                sizes = local_model_sizes()
                if job["model"] in STATE["pool"]:
                    STATE["pool"][job["model"]]["size_mb"] = sizes.get(job["model"])
                STATE["last_error"] = None
            except Exception as err:
                try:
                    http_json(
                        f"{gateway}/api/compute/jobs/{job['id']}/complete",
                        {"token": token, "error": f"model pull failed: {err}"[:2000]},
                        timeout=30,
                    )
                except Exception:
                    pass
                print(f"job {job['id']} model pull failed: {err}")
                STATE["job_state"] = "idle"
                STATE["last_error"] = f"pull failed: {err}"
                time.sleep(2)
                continue

        # Private jobs arrive as Hiro glyphs: decode in memory, never touch
        # disk, and re-encode the response before returning it to the hub.
        if job.get("visibility") == "priv":
            try:
                job["payload"] = json.loads(hiro_decode(job.get("payload_enc", ""), job.get("payload_key", "")))
            except Exception as err:
                try:
                    http_json(
                        f"{gateway}/api/compute/jobs/{job['id']}/complete",
                        {"token": token, "error": f"hiro decode failed: {err}"[:2000]},
                        timeout=30,
                    )
                except Exception:
                    pass
                print(f"job {job['id']} failed to decode: {err}")
                time.sleep(1)
                continue

        STATE["job_state"] = "working"
        STATE["current_job"] = job["model"]
        started = time.time()
        STATE["last_job"] = {
            "id": job["id"],
            "model": job["model"],
            "kind": job.get("kind", "chat"),
            "redacted_prompt": job_preview(job),
            "started_at": time.strftime("%H:%M:%S"),
            "finished_at": None,
            "latency_ms": None,
            "tokens": 0,
            "credits": 0,
            "credit_tier": None,
        }
        print(f"job {job['id']}: {job['model']} ({job.get('kind', 'chat')})")
        try:
            result = run_job(job)
            if job.get("visibility") == "priv":
                result["response"] = hiro_encode(result["response"], job.get("payload_key", ""))
                result["encoded"] = True
            done = http_json(
                f"{gateway}/api/compute/jobs/{job['id']}/complete",
                {"token": token, **result},
                timeout=60,
            )
            STATE["jobs_completed"] += 1
            STATE["tokens"] += result["output_tokens"]
            STATE["credits"] += done.get("credits", 0)
            STATE["credits_tier"] = done.get("tier") or STATE["credits_tier"]
            completion_times.append(time.time())
            # A non-Ollama provider model (Gemini, Mistral, ...) never
            # touches local storage at all, so it must skip BOTH the local
            # pool bookkeeping below (which assumes an `ollama pull`
            # happened) AND the Ollama-specific cloud-auth/quota tracking
            # further down (whose success/failure signal is specifically
            # about ollama.com, not some other provider entirely).
            if detect_external_provider(job.get("model")) or is_bigmoe_model(job.get("model")):
                pass
            elif not is_cloud_model(job.get("model")):
                pool_touch(job["model"])
            if is_cloud_model(job.get("model")):
                cloud_usage.append((time.time(), result["output_tokens"]))
                # A success via the direct-key fallback proves nothing about
                # local `ollama signin` - only a real local-proxy success
                # does. Leaving auth_ok alone here keeps the fallback active
                # for the next job too, instead of wrongly switching back to
                # a local session that was never actually signed in.
                if not result.get("cloud_via_direct_key"):
                    STATE["cloud"]["auth_ok"] = True
                STATE["cloud"]["total_tokens"] += result["output_tokens"]
                if STATE["cloud"].get("real_limit_hit"):
                    # A cloud job just succeeded, so the earlier real
                    # rejection has cleared (Ollama's monthly reset, or it
                    # was transient) - resume advertising cloud models.
                    STATE["cloud"]["real_limit_hit"] = False
                    STATE["cloud"]["real_limit_cleared_at"] = time.time()
                    save_cloud_state()
                threading.Thread(target=refresh_cloud_account, daemon=True).start()
            STATE["last_job"].update(
                {
                    "finished_at": time.strftime("%H:%M:%S"),
                    "latency_ms": int((time.time() - started) * 1000),
                    "tokens": result["output_tokens"],
                    "credits": done.get("credits", 0),
                    "credit_tier": done.get("tier"),
                }
            )
            print(
                f"completed job {job['id']} - {result['output_tokens']} tokens, "
                f"+{done.get('credits', 0)} {done.get('tier') or 'basic'} credits"
            )
            STATE["job_history"] = (STATE.get("job_history") or []) + [{
                "t": time.strftime("%H:%M:%S"),
                "model": job["model"],
                "tokens": result["output_tokens"],
                "credits": done.get("credits", 0),
                "latency_ms": int((time.time() - started) * 1000),
                "ok": True,
            }]
            STATE["job_history"] = STATE["job_history"][-60:]
        except Exception as err:
            STATE["jobs_failed"] += 1
            STATE["last_error"] = str(err)
            if is_cloud_model(job.get("model")):
                error_kind = classify_cloud_error(err)
                if error_kind == "quota":
                    # A REAL rejection from Ollama (429, or a 402/error body
                    # that actually mentions quota/credits) - not our own
                    # self-imposed hourly pacing budget. Record the exact
                    # token count this account produced before hitting it
                    # (the only way to ever learn a real number, since
                    # Ollama exposes no balance API) and stop advertising
                    # cloud models until the retry cooldown allows a probe.
                    if not STATE["cloud"].get("real_limit_hit"):
                        STATE["cloud"]["real_limit_hit"] = True
                        STATE["cloud"]["real_limit_hit_at"] = time.time()
                        STATE["cloud"]["real_limit_hit_tokens"] = STATE["cloud"].get("total_tokens", 0)
                        save_cloud_state()
                        print(
                            f"[{time.strftime('%H:%M:%S')}] REAL cloud limit hit after "
                            f"{STATE['cloud']['real_limit_hit_tokens']} total tokens: {err}"
                        )
                    # A real quota rejection is not an auth problem - leave
                    # auth_ok alone so the dashboard doesn't misreport
                    # "signed out" for what is actually "signed in, capped".
                else:
                    STATE["cloud"]["auth_ok"] = False
                    # Unclassified (or genuinely auth) failure: the login may
                    # have lapsed; check immediately so the node stops (or
                    # resumes) advertising cloud models correctly.
                    threading.Thread(target=verify_cloud_account, daemon=True).start()
            STATE["last_job"]["finished_at"] = time.strftime("%H:%M:%S")
            try:
                http_json(
                    f"{gateway}/api/compute/jobs/{job['id']}/complete",
                    {"token": token, "error": str(err)[:2000]},
                    timeout=30,
                )
            except Exception:
                pass
            print(f"job {job['id']} failed: {err}")
            if "402" in str(err) or "Payment Required" in str(err):
                pw = list(STATE["cloud"].get("paywalled") or [])
                if job.get("model") and job["model"] not in pw:
                    pw.append(job["model"])
                    STATE["cloud"]["paywalled"] = pw
                    save_cloud_state()
            STATE["job_history"] = (STATE.get("job_history") or []) + [{
                "t": time.strftime("%H:%M:%S"),
                "model": job.get("model", ""),
                "tokens": 0,
                "credits": 0,
                "latency_ms": int((time.time() - started) * 1000),
                "ok": False,
            }]
            STATE["job_history"] = STATE["job_history"][-60:]
        if STATE.get("evict_after_job", True):
            _after_job_cleanup(job.get("model"))
        STATE["job_state"] = "idle"
        STATE["current_job"] = None
        time.sleep(1)


def tray_icon_image():
    """Small cloud glyph for the Windows system tray (bottom-right)."""
    try:
        from PIL import Image, ImageDraw
    except Exception:
        return None
    img = Image.new("RGB", (64, 64), "#0b0e14")
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([3, 3, 61, 61], radius=14, fill="#2563eb")
    d.ellipse([16, 18, 30, 32], fill="#ffffff")
    d.ellipse([26, 13, 42, 29], fill="#ffffff")
    d.ellipse([37, 20, 50, 33], fill="#ffffff")
    d.rectangle([25, 32, 40, 43], fill="#ffffff")
    return img


def start_tray(root, ui, build_menu):
    """Tray icon for the worker. Returns the icon or None when unavailable.

    Menu callbacks run on pystray's thread, so they post onto a command queue
    that the tkinter main loop drains (tkinter is not thread-safe).
    """
    try:
        import pystray
        from pystray import Menu, MenuItem
    except Exception:
        return None
    img = tray_icon_image()
    if img is None:
        return None
    icon = pystray.Icon(
        "TokenBrokerWorker",
        img,
        "TokenBroker Worker",
        menu=build_menu(),
    )
    try:
        icon.run_detached()
    except AttributeError:
        threading.Thread(target=icon.run, daemon=True).start()
    ui["icon"] = icon
    return icon


def run_ui(stats_url):
    """Visible worker window: live status, per-job clarity, earnings, and controls."""
    import queue
    import tkinter as tk
    import webbrowser
    from tkinter import ttk, messagebox

    BG = "#0b0e14"
    CARD = "#141925"
    BORDER = "#232a3a"
    TEXT = "#dbe2ef"
    MUTED = "#8b96ab"
    ACCENT = "#4f8cff"
    GOOD = "#38d39f"
    WARN = "#ffb454"
    BAD = "#ff5c72"

    root = tk.Tk()
    root.title("TokenBroker Worker")
    root.geometry("480x720")
    root.configure(bg=BG)
    root.minsize(450, 640)

    header = tk.Frame(root, bg=BG)
    header.pack(fill="x", padx=16, pady=(14, 2))
    tk.Label(header, text="TokenBroker", font=("Segoe UI", 15, "bold"), bg=BG, fg=TEXT).pack(side="left")
    tk.Label(header, text="WORKER", font=("Segoe UI", 10, "bold"), bg=BG, fg=ACCENT).pack(side="left", padx=(6, 0))
    status = tk.Label(root, text="Starting...", font=("Segoe UI", 16, "bold"), bg=BG, fg=WARN)
    status.pack(pady=(6, 0))
    sub = tk.Label(root, text="Opaque compute node - prompts and outputs stay hidden.", bg=BG, fg=MUTED, font=("Segoe UI", 9))
    sub.pack(pady=(0, 8))

    def card(parent, title):
        f = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        tk.Label(f, text=title, bg=CARD, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", padx=8, pady=(6, 0))
        val = tk.Label(f, text="0", bg=CARD, fg=TEXT, font=("Segoe UI", 13, "bold"))
        val.pack(anchor="w", padx=8, pady=(0, 6))
        return f, val

    r1 = tk.Frame(root, bg=BG); r1.pack(fill="x", padx=16, pady=4)
    r2 = tk.Frame(root, bg=BG); r2.pack(fill="x", padx=16, pady=4)
    for row in (r1, r2):
        for i in range(3):
            row.grid_columnconfigure(i, weight=1)
    jobs_card, jobs_val = card(r1, "JOBS")
    tok_card, tok_val = card(r1, "TOKENS")
    cred_card, cred_val = card(r1, "CREDITS")
    rpm_card, rpm_val = card(r2, "REQ/MIN")
    up_card, up_val = card(r2, "UPTIME")
    cloud_card, cloud_val = card(r2, "CLOUD")
    jobs_card.grid(row=0, column=0, sticky="nsew", padx=3)
    tok_card.grid(row=0, column=1, sticky="nsew", padx=3)
    cred_card.grid(row=0, column=2, sticky="nsew", padx=3)
    rpm_card.grid(row=0, column=0, sticky="nsew", padx=3)
    up_card.grid(row=0, column=1, sticky="nsew", padx=3)
    cloud_card.grid(row=0, column=2, sticky="nsew", padx=3)

    info = tk.Label(root, text="", justify="left", anchor="w", bg=BG, fg=TEXT, font=("Consolas", 9))
    info.pack(fill="x", padx=18, pady=(6, 2))

    chart = tk.Canvas(root, height=140, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
    chart.pack(fill="x", padx=16, pady=4)

    tk.Label(root, text="Recent jobs", bg=BG, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=18, pady=(6, 0))
    cols = ("t", "model", "tokens", "credits", "lat", "result")
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT, borderwidth=0, rowheight=20)
    style.configure("Treeview.Heading", background="#0f1420", foreground=MUTED, borderwidth=0, font=("Segoe UI", 8, "bold"))
    tree = ttk.Treeview(root, columns=cols, show="headings", height=6, style="Treeview")
    for c, txt, w in (("t", "Time", 50), ("model", "Model", 160), ("tokens", "Tok", 44), ("credits", "Cred", 46), ("lat", "ms", 42), ("result", "", 62)):
        tree.heading(c, text=txt)
        tree.column(c, width=w, anchor="w" if c in ("t", "model") else "e", stretch=(c == "model"))
    tree.pack(fill="x", padx=16, pady=4)

    last = tk.Label(root, text="", justify="left", anchor="w", bg=BG, fg=WARN, font=("Consolas", 9), wraplength=448)
    last.pack(fill="x", padx=18, pady=4)

    br1 = tk.Frame(root, bg=BG); br1.pack(fill="x", padx=16, pady=(8, 0))
    br2 = tk.Frame(root, bg=BG); br2.pack(fill="x", padx=16, pady=(6, 14))
    for row in (br1, br2):
        for i in range(4):
            row.grid_columnconfigure(i, weight=1)

    def mkbtn(parent, text, cmd, col, row, fg=TEXT, bg="#1a2233"):
        b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg, relief="flat",
                      font=("Segoe UI", 9), activebackground=bg, activeforeground=fg, cursor="hand2")
        b.grid(row=row, column=col, sticky="ew", padx=3, pady=2)
        return b

    ui = {"icon": None}
    ui_commands = queue.Queue()

    def ui_thread_safe(fn):
        ui_commands.put(fn)

    def open_details():
        """Open the folder the worker is installed from (config, logs, uninstaller)."""
        target = app_dir()
        try:
            if sys.platform.startswith("win"):
                os.startfile(target)
            else:
                webbrowser.open("file://" + target)
        except Exception as err:
            STATE["last_error"] = f"could not open install folder: {err}"

    def open_stats():
        webbrowser.open(stats_url)

    def toggle_pause():
        if PAUSE_EVENT.is_set():
            PAUSE_EVENT.clear()
            pause_btn.config(text="Pause")
            STATE["job_state"] = "idle"
        else:
            PAUSE_EVENT.set()
            STATE["job_state"] = "paused"
            pause_btn.config(text="Resume")
        if ui["icon"] is not None:
            try:
                ui["icon"].update_menu()
            except Exception:
                pass

    def quit_worker():
        STOP_EVENT.set()
        root.destroy()

    def uninstall_worker():
        if not messagebox.askyesno(
            "Uninstall TokenBroker Worker",
            "Stop the worker, remove it from startup, and delete its files?\n\nOllama itself is left installed.",
        ):
            return
        STOP_EVENT.set()
        root.withdraw()
        try:
            root.update_idletasks()
        except Exception:
            pass
        target = os.path.join(app_dir(), "uninstall.bat")
        if not os.path.exists(target):
            target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uninstall.bat")
        try:
            _popen_hidden(["cmd", "/c", target])
        except Exception:
            pass
        root.destroy()

    def connect_cloud():
        def do_signin():
            try:
                bin_path = ollama_bin()
                if not bin_path:
                    STATE["last_error"] = "Ollama CLI not found - install Ollama from https://ollama.com"
                    return
                try:
                    proc = _popen_hidden([bin_path, "signin"])
                except FileNotFoundError:
                    proc = _popen_hidden([bin_path, "login"])
                url = None
                lines = []
                deadline = time.time() + 60
                while time.time() < deadline and proc.poll() is None:
                    line = proc.stdout.readline()
                    if line:
                        line = line.strip()
                        lines.append(line)
                        m = re.search(r"https://[^\s\"']+", line)
                        if m and not url:
                            url = m.group(0)
                            STATE["last_error"] = f"Open this link to finish sign-in: {url}"
                            try:
                                import webbrowser
                                webbrowser.open(url)
                            except Exception:
                                pass
                    else:
                        time.sleep(0.2)
                try:
                    rest = proc.stdout.read()
                    if rest:
                        lines.append(rest.strip())
                except Exception:
                    pass
                proc.wait(timeout=5)
                output = "\n".join(lines)
                STATE["cloud"]["account"] = ollama_account_from_signin(output)
                STATE["cloud"]["login"] = proc.returncode == 0
                STATE["cloud"]["auth_ok"] = None
                if proc.returncode == 0:
                    STATE["last_error"] = None
                else:
                    tip = f" Open {url} to finish." if url else ""
                    STATE["last_error"] = f"ollama signin: {output.strip()[:300]}{tip}"
            except Exception as err:
                STATE["last_error"] = f"ollama signin: {err}"

        threading.Thread(target=do_signin, daemon=True).start()

    def toggle_cloud():
        STATE["cloud"]["enabled"] = not STATE["cloud"].get("enabled", False)
        save_cloud_state()

    def toggle_private():
        STATE["private_jobs"] = not STATE.get("private_jobs", True)
        save_config_pref("private_jobs", STATE["private_jobs"])

    def hide_to_tray():
        root.withdraw()
        if ui["icon"] is not None:
            try:
                ui["icon"].update_menu()
            except Exception:
                pass

    def show_from_tray():
        root.deiconify()
        root.lift()
        root.focus_force()

    def on_close():
        if ui["icon"] is not None:
            hide_to_tray()
        else:
            quit_worker()

    def on_minimize(_event):
        if ui["icon"] is not None and root.state() == "iconic":
            root.after(150, hide_to_tray)

    def build_tray_menu():
        from pystray import Menu, MenuItem
        paused = PAUSE_EVENT.is_set()
        return Menu(
            MenuItem("Show window", lambda: ui_thread_safe(show_from_tray), default=True),
            MenuItem("Hide window", lambda: ui_thread_safe(hide_to_tray)),
            MenuItem("Resume" if paused else "Pause", lambda: ui_thread_safe(toggle_pause)),
            MenuItem("Sign in to Ollama", lambda: ui_thread_safe(connect_cloud)),
            MenuItem("Accept private jobs: " + ("on" if STATE.get("private_jobs", True) else "off"), lambda: ui_thread_safe(toggle_private)),
            MenuItem("Uninstall worker...", lambda: ui_thread_safe(uninstall_worker)),
            Menu.SEPARATOR,
            MenuItem("Quit", lambda: (ui["icon"].stop() if ui["icon"] is not None else None, ui_thread_safe(quit_worker))),
        )

    mkbtn(br1, "Open folder", open_details, 0, 0, fg="#0b0e14", bg=ACCENT)
    mkbtn(br1, "Sign in", connect_cloud, 1, 0)
    cloud_btn = mkbtn(br1, "Cloud off", toggle_cloud, 2, 0)
    mkbtn(br1, "Quit", quit_worker, 3, 0, fg="#ffffff", bg=BAD)
    private_btn = mkbtn(br2, "Priv on", toggle_private, 0, 0)
    pause_btn = mkbtn(br2, "Pause", toggle_pause, 1, 0)
    mkbtn(br2, "Uninstall", uninstall_worker, 2, 0, fg="#ffb454", bg="#2a2018")
    mkbtn(br2, "Stats", open_stats, 3, 0)

    start_tray(root, ui, build_tray_menu)
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.bind("<Unmap>", on_minimize)

    def fmt_uptime(secs):
        secs = int(secs or 0)
        h, rem = divmod(secs, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"

    def refresh():
        s = STATE
        st = s.get("job_state", "idle")
        if s.get("status") == "gateway unreachable":
            label, color = "Offline - gateway unreachable", BAD
        elif s.get("status") in ("flagged", "revoked"):
            label, color = "Suspended by network", BAD
        elif st == "paused":
            label, color = "Paused", MUTED
        elif st == "working":
            label, color = f"Working: {s.get('current_job')}", GOOD
        elif st == "pulling":
            label, color = f"Pulling model: {s.get('current_job')}", WARN
        else:
            label, color = "Running - idle", GOOD
        status.config(text=label, fg=color)
        if ui["icon"] is not None:
            try:
                ui["icon"].title = f"TokenBroker Worker - {label}"
            except Exception:
                pass

        jobs_val.config(text=f"{s.get('jobs_completed', 0)} done / {s.get('jobs_failed', 0)} fail")
        tok_val.config(text=f"{s.get('tokens', 0):,}")
        cred_val.config(text=f"{s.get('credits', 0):,} {s.get('credits_tier') or ''}".strip())
        rpm_val.config(text=f"{s.get('rpm', 0)}")
        up_val.config(text=fmt_uptime(time.time() - s.get("started_at", time.time())))
        cloud = s.get("cloud") or {}
        if cloud.get("enabled") and cloud.get("auth_ok") is True:
            cloud_val.config(text=cloud.get("account") or "signed in", fg=GOOD)
        elif cloud.get("enabled") and cloud.get("auth_ok") is False:
            cloud_val.config(text="signed out", fg=BAD)
        else:
            cloud_val.config(text="off" if not cloud.get("enabled") else "?", fg=MUTED)

        quality = s.get("quality") or {}
        verified = s.get("worker_verified")
        cloud_btn.config(text="Cloud on" if cloud.get("enabled") else "Cloud off")
        private_btn.config(text="Priv on" if s.get("private_jobs", True) else "Priv off")
        info.config(
            text=(
                f"Gateway  : {s.get('gateway', '-')}\n"
                f"Identity : fp {str(s.get('fingerprint') or '-')[:12]}  build {'verified' if verified is True else 'MODIFIED' if verified is False else 'n/a'}\n"
                f"Storage  : {s.get('storage_gb', 0):.0f} GB model budget  |  VM score: {s.get('vm', {}).get('score')}\n"
                f"Rank     : {quality.get('tier') or '-'}  est {quality.get('tps') or 0} tok/s  {quality.get('daily_credits') or 0}/day\n"
                f"Cloud    : {'on' if cloud.get('enabled') else 'off'}  used {cloud.get('used_tokens_per_hour', 0):,}/{cloud.get('quota_per_hour', 0):,}  rem {cloud.get('remaining', 0):,}\n"
                f"Private  : {'accepting jobs' if s.get('private_jobs', True) else 'off'}  |  Pool: {s.get('pool_count', 0)} models, {s.get('pool_mb', 0)} MB"
            )
        )

        chart.delete("all")
        hist = s.get("history") or []
        n = len(hist)
        if n:
            w, h, pad_l, pad_t, pad_b = 430, 118, 8, 8, 20
            iw, ih = w - pad_l - 8, h - pad_t - pad_b
            max_rpm = max(1, max(x.get("rpm", 0) for x in hist))
            max_tok = max(1, max(x.get("tokens", 0) for x in hist))
            rpm_pts, tok_pts = [], []
            for i, x in enumerate(hist):
                px = pad_l + (i / max(1, n - 1)) * iw
                rpm_pts.extend((px, pad_t + ih - (x.get("rpm", 0) / max_rpm) * ih))
                tok_pts.extend((px, pad_t + ih - (x.get("tokens", 0) / max_tok) * ih))
                if not x.get("online"):
                    chart.create_rectangle(px - 2, pad_t, px + 2, pad_t + ih, fill="#7f1d1d", outline="")
            if len(rpm_pts) > 2:
                chart.create_line(*rpm_pts, fill=ACCENT, width=2)
            if len(tok_pts) > 2:
                chart.create_line(*tok_pts, fill=GOOD, width=2)
            chart.create_text(
                pad_l + 4, h - 6, anchor="w",
                text=f"blue req/min (max {max_rpm})  green tok/min (max {max_tok})  red bar = offline",
                fill=MUTED, font=("Segoe UI", 8),
            )

        tree.delete(*tree.get_children())
        for j in reversed((s.get("job_history") or [])[-60:]):
            tree.insert(
                "", "end",
                values=(
                    j.get("t", ""),
                    j.get("model", ""),
                    j.get("tokens", ""),
                    j.get("credits", ""),
                    j.get("latency_ms", "") if j.get("latency_ms") is not None else "",
                    "ok" if j.get("ok") else "FAIL",
                ),
            )

        err = s.get("last_error")
        last.config(text=err or "", fg=WARN if err else MUTED)

        root.after(2000, refresh)

    def drain_ui_commands():
        try:
            while True:
                fn = ui_commands.get_nowait()
                try:
                    fn()
                except Exception:
                    pass
        except queue.Empty:
            pass
        root.after(200, drain_ui_commands)

    drain_ui_commands()
    refresh()
    root.mainloop()


def main():
    global STATS_TOKEN
    ap = argparse.ArgumentParser(description="TokenBroker compute worker")
    ap.add_argument("--config", default=None, help="Path to worker-config.json")
    ap.add_argument("--gateway", default=None)
    ap.add_argument("--token", default=None)
    ap.add_argument("--name", default="My Worker")
    ap.add_argument("--interval", type=int, default=30)
    ap.add_argument("--headless", action="store_true", help="Run without the UI window")
    ap.add_argument("--no-private-jobs", action="store_true", help="Never claim private (Hiro-encoded) jobs")
    ap.add_argument("--dry-run", action="store_true", help="Test mode: return a canned response instead of calling Ollama")
    ap.add_argument(
        "--multi",
        action="store_true",
        help="Allow multiple worker instances on one machine (e.g. several workers sharing one Ollama server)",
    )
    args = ap.parse_args()

    gateway = args.gateway
    token = args.token
    stats_token = STATS_TOKEN
    config_candidates = [args.config, os.path.join(app_dir(), "worker-config.json")]
    cfg = None
    for candidate in config_candidates:
        if candidate and os.path.exists(candidate):
            with open(candidate, encoding="utf-8-sig") as f:  # tolerate a BOM (PowerShell writes one)
                cfg = json.load(f)
            break
    if cfg and isinstance(cfg, dict):
        gateway = gateway or cfg.get("gateway")
        token = token or cfg.get("token")
        stats_token = cfg.get("stats_token") or STATS_TOKEN
        if cfg.get("hiro_path"):
            os.environ["HIRO_PATH"] = cfg["hiro_path"]
    else:
        cfg = {}
    args.name = cfg.get("name", args.name)
    private_jobs = cfg.get("private_jobs", True)
    if args.no_private_jobs:
        private_jobs = False
    STATE["private_jobs"] = private_jobs
    STATE["dry_run"] = args.dry_run
    configure_bigmoe(cfg.get("bigmoe"))
    STATE["cloud"]["enabled"] = bool(cfg.get("cloud_enabled", False))
    STATE["cloud"]["quota_per_hour"] = int(cfg.get("cloud_quota_per_hour", 100000) or 100000)
    STATE["cloud"]["remaining"] = STATE["cloud"]["quota_per_hour"]
    STATE["cloud"]["installed"] = ollama_bin() is not None
    STATE["max_pool_idle_hours"] = float(cfg.get("max_pool_idle_hours", 2) or 2)
    STATE["evict_after_job"] = str(cfg.get("evict_after_job", True)).lower() not in (
        "false",
        "0",
        "no",
    )
    # Remember the last verified ollama.com account and cloud toggle across
    # restarts, then re-verify the live session in the background so cloud
    # models are only advertised when the session is actually valid.
    load_cloud_state()

    def _boot_verify():
        for _ in range(3):
            verify_cloud_account()
            if STATE["cloud"].get("auth_ok") is True:
                return
            time.sleep(5)

    threading.Thread(target=_boot_verify, daemon=True).start()

    def _probe_subscription():
        """Probe a known pay-gated Ollama model to learn the account tier.

        Ollama returns HTTP 402 immediately when the signed-in ollama.com
        account cannot serve a pay-gated model, so a tiny 1-token probe tells
        us whether this worker is on a free or paying plan. Free cloud models
        are never used as probes (they would 200 on a free account).
        """
        if not ollama_bin():
            return
        candidates = [
            cfg.get("cloud_probe_model", ""),
            "kimi-k3:cloud",
            "Beelzebub4883/arriella-ascension-dsv4flash-cloud",
            "deepseek-v4-flash:0731",
        ]
        candidates = [m for m in candidates if m]
        for attempt in range(3):
            for probe in candidates:
                try:
                    http_json(
                        OLLAMA + "/api/chat",
                        {"model": probe, "messages": [{"role": "user", "content": "ping"}], "stream": False, "options": {"num_predict": 1}},
                        timeout=30,
                    )
                    STATE["cloud"]["subscription"] = "paying"
                    save_cloud_state()
                    return
                except Exception as err:
                    if getattr(err, "code", None) == 402 or "402" in str(err) or "Payment Required" in str(err):
                        STATE["cloud"]["subscription"] = "free"
                        save_cloud_state()
                        return
            time.sleep(5)
        STATE["cloud"]["subscription"] = "unknown"
        save_cloud_state()

    threading.Thread(target=_probe_subscription, daemon=True).start()
    # Restore the on-demand-pull tracker and evict anything already idle past
    # the limit (e.g. pulls from a previous session).
    load_pool_state()
    threading.Thread(
        target=lambda: evict_idle_pool(STATE.get("max_pool_idle_hours", 2)),
        daemon=True,
    ).start()
    try:
        STATE["storage_gb"] = max(0, float(cfg.get("storage_gb") or 20))
    except Exception:
        STATE["storage_gb"] = 20
    if not gateway or not token:
        print("Missing gateway URL or worker token. Use --gateway/--token or a worker-config.json.")
        sys.exit(1)

    if another_instance_running() and not args.multi:
        _log_crash("another instance is already running; exiting cleanly")
        print("Another TokenBroker worker is already running on this machine. Exiting.")
        sys.exit(0)

    STATE["gateway"] = gateway.rstrip("/")
    STATS_TOKEN = stats_token
    write_pid_file()
    stats_server, stats_port = start_stats_server()
    stats_url = f"http://127.0.0.1:{stats_port}/?token={STATS_TOKEN}"
    print(f"TokenBroker worker: {args.name}")
    print(f"Stats window: {stats_url}")
    STATE["gpu"] = detect_gpu()
    print(f"GPU: {STATE['gpu'] or 'not detected (CPU mode)'}")
    STATE["fingerprint"], hw = hardware_fingerprint()
    STATE["vm"] = vm_detection(hw)
    STATE["worker_hash"] = worker_self_hash()
    print(
        f"Worker hash: {STATE['worker_hash'][:16]}..."
        if STATE["worker_hash"]
        else "Worker hash: unavailable"
    )
    hw_payload = {
        "ram_gb": hw.get("ramGb"),
        "cpu": hw.get("cpu"),
        "cpu_cores": hw.get("cores"),
        "gpu": STATE["gpu"],
    }
    print(f"Hardware fingerprint: {STATE['fingerprint'][:12]}...")
    print(
        f"VM suspicion: {STATE['vm']['score']}"
        + (f" ({', '.join(STATE['vm']['reasons'])})" if STATE['vm']['reasons'] else "")
    )
    STATE["models"] = local_models()
    print(f"Local Ollama models: {', '.join(STATE['models']) or 'NONE'}")

    if args.headless:
        worker_loop(STATE["gateway"], token, args.interval, hw_payload, private_jobs)
        return

    try:
        import tkinter  # noqa: F401

        threading.Thread(
            target=worker_loop,
            args=(STATE["gateway"], token, args.interval, hw_payload, private_jobs),
            daemon=True,
        ).start()
        run_ui(stats_url)
    except Exception as err:
        _log_crash(f"UI unavailable ({err}); running headless")
        worker_loop(STATE["gateway"], token, args.interval, hw_payload, private_jobs)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nworker stopped")
        sys.exit(0)
