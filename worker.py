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


def _run(args, **kwargs):
    """subprocess.run that never flashes a console window on Windows.

    The worker is a windowed app (PyInstaller --noconsole), but child console
    processes (nvidia-smi, powershell, ollama) would otherwise pop a cmd
    window on every heartbeat. CREATE_NO_WINDOW keeps everything invisible.
    """
    if sys.platform.startswith("win"):
        kwargs.setdefault(
            "creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
    return subprocess.run(args, **kwargs)


def _popen_hidden(args, **kwargs):
    """subprocess.Popen that never flashes a console window (Windows)."""
    if sys.platform.startswith("win"):
        kwargs.setdefault(
            "creationflags", getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        )
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
    "storage_gb": 20,
    "gateway": None,
    "fingerprint": None,
    "vm": {"score": 0, "reasons": []},
    "quality": None,
    "worker_hash": None,
    "worker_verified": None,
    "history": [],
    "rpm": 0,
    "pool": {},
    "pool_count": 0,
    "pool_mb": 0,
    "pool_evictions": 0,
    "max_pool_idle_hours": 2,
    "cloud": {
        "enabled": False,
        "auth_ok": None,
        "used_tokens_per_hour": 0,
        "quota_per_hour": 100000,
        "remaining": 100000,
        "login": None,
        "account": None,
        "installed": None,
        "total_tokens": 0,
    },
}

PAUSE_EVENT = threading.Event()
STOP_EVENT = threading.Event()

WINDOWS_HW_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$cs=Get-CimInstance Win32_ComputerSystem
$bios=Get-CimInstance Win32_BIOS
$cpu=Get-CimInstance Win32_Processor
$board=Get-CimInstance Win32_BaseBoard
$disks=@(Get-CimInstance Win32_DiskDrive)
$macs=@(Get-NetAdapter -Physical | Select-Object -ExpandProperty MacAddress)
$guid=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
[pscustomobject]@{
  manufacturer=$cs.Manufacturer; model=$cs.Model; hypervisor=$cs.HypervisorPresent
  biosMan=$bios.Manufacturer; biosSer=$bios.SerialNumber
  cpu=$cpu.Name; cpuId=$cpu.ProcessorId
  cores=($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
  ramGb=[math]::Round($cs.TotalPhysicalMemory/1GB,1)
  boardSer=$board.SerialNumber; guid=$guid
  macs=($macs -join ','); disks=(($disks | ForEach-Object Model) -join ',')
  diskSers=(($disks | ForEach-Object SerialNumber) -join ',')
} | ConvertTo-Json -Compress
"""


def powershell_json(script):
    try:
        out = _run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=25,
        )
        if out.returncode == 0 and out.stdout.strip():
            return json.loads(out.stdout.strip().splitlines()[-1])
    except Exception:
        pass
    return None


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return ""


def gather_hw():
    if sys.platform.startswith("win"):
        info = powershell_json(WINDOWS_HW_SCRIPT)
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
            out = _run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if out.returncode == 0 and out.stdout.strip():
                return float(out.stdout.strip())
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
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


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
    """Extract the signed-in ollama.com username from `ollama signin` output."""
    m = re.search(r"already signed in as user '([^']+)'", output or "")
    if m:
        return m.group(1)
    m = re.search(r"(?:signed|logged) in as\s+([^\s']+)", output or "", re.IGNORECASE)
    if m:
        return m.group(1)
    return None


CLOUD_LOCK = threading.Lock()


def cloud_state_path():
    """Persistent cloud-auth memory, stored next to worker-config.json so the
    worker remembers the signed-in ollama.com user across restarts/reboots."""
    return os.path.join(app_dir(), "worker-cloud.json")


def load_cloud_state():
    """Restore the last verified ollama.com account + cloud toggle. Ollama's
    own session lives in the running Ollama server; this file lets the worker
    show the signed-in user immediately and re-verify on boot."""
    try:
        with open(cloud_state_path()) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return
        for key in ("account", "login", "auth_ok", "verified_at", "enabled"):
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
    valid; when signed out it waits for a browser flow, so a short timeout
    means signed out. Updates STATE and persists it so the worker remembers
    the logged-in user and never advertises cloud models it cannot serve."""
    with CLOUD_LOCK:
        try:
            bin_path = ollama_bin()
            if not bin_path:
                STATE["cloud"]["auth_ok"] = False
                STATE["cloud"]["login"] = False
                STATE["cloud"]["verified_at"] = time.time()
                save_cloud_state()
                return
            proc = _run(
                [bin_path, "signin"], capture_output=True, text=True, timeout=8
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            acct = ollama_account_from_signin(output)
            if proc.returncode == 0 and acct:
                STATE["cloud"]["account"] = acct
                STATE["cloud"]["login"] = True
                STATE["cloud"]["auth_ok"] = True
                STATE["cloud"]["verified_at"] = time.time()
                save_cloud_state()
                return
        except Exception:
            pass
        STATE["cloud"]["auth_ok"] = False
        STATE["cloud"]["login"] = False
        STATE["cloud"]["verified_at"] = time.time()
        save_cloud_state()


def refresh_cloud_account():
    """After a cloud job, re-verify (and persist) the ollama.com account."""
    verify_cloud_account()


def advertised_models(cloud_enabled, exhausted=False):
    """Models this worker will accept. Cloud-gated models are only offered
    when the worker has Ollama Cloud enabled, the ollama.com session is
    verified (auth_ok True), AND quota remains; an exhausted or signed-out
    node stops advertising cloud models entirely so the hub never assigns a
    cloud job it cannot run."""
    models = local_models()
    auth_ok = STATE["cloud"].get("auth_ok") is True
    if cloud_enabled and auth_ok and not exhausted:
        return models
    return [m for m in models if not is_cloud_model(m)]


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
    model = job["model"]
    kind = job.get("kind", "chat")
    payload = job.get("payload") or {}
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
            and STATE["cloud"].get("remaining", 0) <= 0
            and cloud_used > 0
        )
        # Re-verify the ollama.com session every 10 minutes so a lapsed login
        # is detected promptly and cloud models stop being advertised (and
        # resume as soon as the user signs back in).
        if time.time() - cloud_last_verify > 600:
            cloud_last_verify = time.time()
            threading.Thread(target=verify_cloud_account, daemon=True).start()
        # Idle-pool eviction sweep: drop system-pulled models unused for more
        # than max_pool_idle_hours so a node never accumulates disk usage.
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
            }
        ])[-40:]

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
                    "visibility": "all" if private_jobs else "pub",
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
        if job.get("model") not in STATE["models"]:
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
            if not is_cloud_model(job.get("model")):
                pool_touch(job["model"])
            if is_cloud_model(job.get("model")):
                cloud_usage.append((time.time(), result["output_tokens"]))
                STATE["cloud"]["auth_ok"] = True
                STATE["cloud"]["total_tokens"] += result["output_tokens"]
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
        except Exception as err:
            STATE["jobs_failed"] += 1
            STATE["last_error"] = str(err)
            if is_cloud_model(job.get("model")):
                STATE["cloud"]["auth_ok"] = False
                # The failure may be a lapsed login; check immediately so the
                # node stops (or resumes) advertising cloud models correctly.
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
    """Visible worker window: status, hardware, earnings, and controls."""
    import queue
    import tkinter as tk
    import webbrowser

    root = tk.Tk()
    root.title("TokenBroker Worker")
    root.geometry("430x540")
    root.configure(bg="#0f1115")

    status = tk.Label(root, text="Starting...", font=("Segoe UI", 17, "bold"), bg="#0f1115", fg="#fbbf24")
    status.pack(pady=(18, 2))
    sub = tk.Label(root, text="Opaque compute node - prompts and outputs stay hidden.", bg="#0f1115", fg="#9ca3af", font=("Segoe UI", 9))
    sub.pack(pady=(0, 8))
    info = tk.Label(root, text="", justify="left", anchor="w", bg="#0f1115", fg="#e5e7eb", font=("Consolas", 10))
    info.pack(fill="x", padx=20, pady=6)
    chart = tk.Canvas(root, width=390, height=130, bg="#161922", highlightthickness=0)
    chart.pack(fill="x", padx=20, pady=4)
    last = tk.Label(root, text="", justify="left", anchor="w", bg="#0f1115", fg="#9ca3af", font=("Consolas", 9), wraplength=390)
    last.pack(fill="x", padx=20, pady=4)
    buttons = tk.Frame(root, bg="#0f1115")
    buttons.pack(pady=10)

    ui = {"icon": None}
    ui_commands = queue.Queue()

    def ui_thread_safe(fn):
        """Post a UI action from another thread onto the tkinter main loop."""
        ui_commands.put(fn)

    def open_details():
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

    def connect_cloud():
        def do_signin():
            try:
                bin_path = ollama_bin()
                if not bin_path:
                    STATE["last_error"] = (
                        "Ollama CLI not found - install Ollama from https://ollama.com"
                    )
                    return
                # Ollama >= 0.30 uses `signin`; older builds used `login`.
                try:
                    proc = _popen_hidden([bin_path, "signin"])
                except FileNotFoundError:
                    proc = _popen_hidden([bin_path, "login"])
                # The browser flow prints an auth URL. Show it live in the
                # worker status AND open it so the user can complete sign-in -
                # the window is hidden, so we can't rely on console output.
                url = None
                lines = []
                deadline = time.time() + 300
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
        # Minimizing (iconify) tucks the worker into the tray (bottom-right),
        # so it stays available 24/7 without occupying the taskbar.
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
            Menu.SEPARATOR,
            MenuItem(
                "Quit",
                lambda: (
                    ui["icon"].stop() if ui["icon"] is not None else None,
                    ui_thread_safe(quit_worker),
                ),
            ),
        )

    tk.Button(buttons, text="Open details", command=open_details, bg="#2563eb", fg="white", relief="flat", padx=12, pady=4).pack(side="left", padx=5)
    tk.Button(buttons, text="Sign in", command=connect_cloud, bg="#161922", fg="white", relief="flat", padx=12, pady=4).pack(side="left", padx=5)
    cloud_btn = tk.Button(buttons, text="Cloud off", command=toggle_cloud, bg="#161922", fg="white", relief="flat", padx=12, pady=4)
    cloud_btn.pack(side="left", padx=5)
    pause_btn = tk.Button(buttons, text="Pause", command=toggle_pause, bg="#161922", fg="white", relief="flat", padx=12, pady=4)
    pause_btn.pack(side="left", padx=5)
    tk.Button(buttons, text="Quit", command=quit_worker, bg="#7f1d1d", fg="white", relief="flat", padx=12, pady=4).pack(side="left", padx=5)

    start_tray(root, ui, build_tray_menu)
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.bind("<Unmap>", on_minimize)

    def refresh():
        s = STATE
        st = s.get("job_state", "idle")
        if s.get("status") == "gateway unreachable":
            label, color = "Offline - gateway unreachable", "#ef4444"
        elif s.get("status") in ("flagged", "revoked"):
            label, color = "Suspended by network", "#ef4444"
        elif st == "paused":
            label, color = "Paused", "#9ca3af"
        elif st == "working":
            label, color = f"Working: {s.get('current_job')}", "#22c55e"
        elif st == "pulling":
            label, color = f"Pulling model: {s.get('current_job')}", "#fbbf24"
        else:
            label, color = "Running - idle", "#22c55e"
        status.config(text=label, fg=color)
        if ui["icon"] is not None:
            try:
                ui["icon"].title = f"TokenBroker Worker - {label}"
            except Exception:
                pass
        quality = s.get("quality") or {}
        verified = s.get("worker_verified")
        cloud = s.get("cloud") or {}
        cloud_btn.config(text="Cloud on" if cloud.get("enabled") else "Cloud off")
        info.config(
            text=(
                f"Gateway : {s.get('gateway', '-')}\n"
                f"GPU     : {s.get('gpu') or 'CPU only'}\n"
                f"Storage : {s.get('storage_gb', 0):.0f}GB model budget\n"
                f"CPU     : {s.get('cpu_pct', 0):.0f}%   GPU util: {s.get('gpu_util') or 0:.0f}%\n"
                f"Jobs    : {s.get('jobs_completed', 0)} done / {s.get('jobs_failed', 0)} failed\n"
                f"Tokens  : {s.get('tokens', 0):,}\n"
                f"Credits : {s.get('credits', 0):,} {s.get('credits_tier') or ''}\n"
                f"Rank    : {quality.get('tier') or '-'}   est. {quality.get('tps') or 0} tok/s   "
                f"{quality.get('daily_credits') or 0}/day\n"
                f"Fingerprint: {str(s.get('fingerprint') or '-')[:16]}\n"
                f"VM check: {s.get('vm', {}).get('score')}   "
                f"Build: {'verified' if verified is True else 'MODIFIED' if verified is False else 'n/a'}\n"
                f"Cloud: {'on' if cloud.get('enabled') else 'off'} | auth "
                f"{'ok' if cloud.get('auth_ok') is True else 'no' if cloud.get('auth_ok') is False else '?'} | "
                f"acct {'hidden (private mode)' if s.get('private_mode') else (cloud.get('account') if cloud.get('login') else ('signed out' if cloud.get('auth_ok') is False else 'not signed in'))} | "
                f"used {cloud.get('used_tokens_per_hour', 0):,} / {cloud.get('quota_per_hour', 0):,} "
                f"(rem {cloud.get('remaining', 0):,})\n"
                f"Cloud: installed {'yes' if cloud.get('installed') else 'no'} | "
                f"burned {cloud.get('total_tokens', 0):,} tokens this session\n"
                f"Pool: {s.get('pool_count', 0)} models, {s.get('pool_mb', 0)} MB - "
                f"evict idle >{s.get('max_pool_idle_hours', 2)}h (evictions: {s.get('pool_evictions', 0)})"
            )
        )
        chart.delete("all")
        hist = s.get("history") or []
        n = len(hist)
        if n:
            w, h = 390, 130
            pad_l, pad_b = 8, 18
            iw, ih = w - pad_l - 8, h - pad_b - 16
            max_rpm = max(1, max(x.get("rpm", 0) for x in hist))
            for i, x in enumerate(hist):
                x0 = pad_l + (i / max(1, n - 1)) * iw
                x1 = pad_l + ((i + 1) / max(1, n - 1)) * iw
                y0 = 4
                y1 = y0 + 14 if x.get("online") else y0 + 3
                chart.create_rectangle(
                    x0, y0, x1, y1,
                    fill="#22c55e" if x.get("online") else "#ef4444",
                    outline="",
                )
            pts = []
            for i, x in enumerate(hist):
                px = pad_l + (i / max(1, n - 1)) * iw
                py = 22 + ih - (x.get("rpm", 0) / max_rpm) * ih
                pts.extend((px, py))
            if len(pts) > 2:
                chart.create_line(*pts, fill="#60a5fa", width=2)
            chart.create_text(
                pad_l + 4,
                h - 4,
                anchor="w",
                text=f"green=online · blue=requests/min (max {max_rpm}) · last {n} samples",
                fill="#9ca3af",
                font=("Segoe UI", 8),
            )
        job = s.get("last_job")
        if job:
            last.config(
                text=(
                    f"Last job: {job.get('model')} ({job.get('kind')}) - "
                    f"{job.get('tokens', 0)} tokens, +{job.get('credits', 0)} {job.get('credit_tier') or ''}\n"
                    f"Prompt: {job.get('redacted_prompt')} (redacted)"
                )
            )
        else:
            last.config(text="Last job: none yet")
        root.after(2000, refresh)

    def drain_ui_commands():
        try:
            while True:
                ui_commands.get_nowait()()
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
            with open(candidate) as f:
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
    threading.Thread(target=verify_cloud_account, daemon=True).start()
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
