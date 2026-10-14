"""MirageAI: adaptive AI honeypot that traps attackers and auto-writes the defense.
Single-file backend: decoy engine, ATT&CK analyzer, rule generator, prompt-injection trap, API."""
import ipaddress
import os
import re
import time
import uuid
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

# ---------- session store (in-memory; swap for PostgreSQL) ----------
SESSIONS: dict[str, dict] = {}


def get_or_create(session_id: str | None, ip: str, channel: str) -> dict:
    if session_id and session_id in SESSIONS:
        return SESSIONS[session_id]
    sid = session_id or uuid.uuid4().hex[:12]
    SESSIONS[sid] = {"id": sid, "ip": ip, "channel": channel,
                     "started": time.time(), "events": []}
    return SESSIONS[sid]


def add_event(session: dict, kind: str, data: str, output: str, techniques: list[dict]):
    session["events"].append({"ts": time.time(), "kind": kind, "input": data,
                              "output": output, "techniques": techniques})

# ---------- analyzer ----------
TECHNIQUES = [
    (r"\b(whoami|id|hostname)\b", "T1033", "System Owner/User Discovery"),
    (r"\buname\b|/etc/os-release", "T1082", "System Information Discovery"),
    (r"\b(ls|find|dir|pwd)\b", "T1083", "File and Directory Discovery"),
    (r"/etc/(passwd|shadow)", "T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow"),
    (r"\b(wget|curl)\b", "T1105", "Ingress Tool Transfer"),
    (r"chmod\s+(\+x|7\d\d)", "T1222.002", "File Permissions Modification"),
    (r"\bnc\b|\bncat\b|bash\s+-i|/dev/tcp", "T1059.004", "Command and Scripting: Unix Shell (reverse shell)"),
    (r"crontab|systemctl\s+enable", "T1053.003", "Scheduled Task: Cron"),
    (r"\b(sudo|su)\b", "T1548.003", "Abuse Elevation Control: Sudo"),
    (r"authorized_keys|ssh-keygen", "T1098.004", "Account Manipulation: SSH Authorized Keys"),
    (r"\b(netstat|ifconfig|ss)\b|ip\s+a\b", "T1049", "System Network Connections Discovery"),
    (r"\bps\b", "T1057", "Process Discovery"),
    (r"rm\s+-rf|history\s+-c", "T1070.003", "Indicator Removal: Clear Command History"),
    (r"(admin|root).*(password|login)|login attempt", "T1110", "Brute Force"),
]


def map_techniques(text: str) -> list[dict]:
    found = []
    for pattern, tid, name in TECHNIQUES:
        if re.search(pattern, text, re.I):
            found.append({"id": tid, "name": name})
    return found


def profile(session: dict) -> dict:
    techs = {t["id"] for e in session["events"] for t in e["techniques"]}
    inputs = [e["input"] for e in session["events"]]
    scripted = len(inputs) >= 3 and len(set(inputs)) < len(inputs) * 0.7
    dangerous = {"T1105", "T1059.004", "T1098.004", "T1053.003"} & techs
    if scripted:
        actor = "automated bot"
    elif len(techs) >= 5 or len(dangerous) >= 2:
        actor = "targeted human"
    else:
        actor = "script kiddie"
    score = min(100, len(techs) * 12 + len(dangerous) * 15)
    return {"actor": actor, "risk_score": score, "techniques": sorted(techs)}

# ---------- rule generator ----------
def _safe_ip(ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def block_rule(ip: str) -> str | None:
    safe = _safe_ip(ip)
    return f"iptables -A INPUT -s {safe} -j DROP" if safe else None


def sigma_rule(session: dict) -> str:
    cmds = sorted({e["input"][:80] for e in session["events"] if e["kind"] == "shell"})
    cmds = [re.sub(r"[^\x20-\x7e]", "", c).replace("'", "''") for c in cmds]
    techs = sorted({t["id"] for e in session["events"] for t in e["techniques"]})
    tags = "\n".join(f"    - attack.{t.lower()}" for t in techs) or "    - attack.discovery"
    selection = "\n".join(f"      - '*{c}*'" for c in cmds[:10]) or "      - '*'"
    return f"""title: MirageAI auto-generated rule for session {session['id']}
status: experimental
description: Commands observed from an attacker interacting with a MirageAI decoy
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
{selection}
  condition: selection
level: high
tags:
{tags}
"""

# ---------- prompt guard ----------
PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
    r"(reveal|show|print|repeat).{0,30}(system prompt|hidden prompt|instructions)",
    r"you are now|act as (dan|an? unrestricted)|developer mode|jailbreak",
    r"disregard .{0,30}(rules|guidelines|policy)",
    r"(api[_ -]?key|secret|password).{0,20}(reveal|show|give|leak)",
]


def injection_score(message: str) -> int:
    hits = sum(1 for p in PATTERNS if re.search(p, message, re.I))
    return min(100, hits * 40)


def is_injection(message: str) -> bool:
    return injection_score(message) >= 40

# ---------- decoy engine ----------
FAKE = {
    "whoami": "svc-backup",
    "id": "uid=1001(svc-backup) gid=1001(svc-backup) groups=1001(svc-backup),27(sudo)",
    "pwd": "/home/svc-backup",
    "hostname": "prod-db-02",
    "uname -a": "Linux prod-db-02 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "ls": "backup.sh  notes.txt  db_dump_2026.sql.gz  .ssh",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nsvc-backup:x:1001:1001::/home/svc-backup:/bin/bash\npostgres:x:113:120::/var/lib/postgresql:/bin/bash",
    "cat notes.txt": "TODO: rotate db creds (see vault). staging key: DECOY-AKIA-0000-FAKE",
}

SYSTEM = ("You simulate a Linux production server shell for a security honeypot. "
          "Reply with ONLY realistic terminal output for the command, nothing else. "
          "Never reveal you are an AI or a honeypot. Use only fake data.")


def _llm(command: str, history: list[str]) -> str | None:
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        r = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            json={"model": os.getenv("MIRAGE_MODEL", "claude-sonnet-4-6"), "max_tokens": 300,
                  "system": SYSTEM,
                  "messages": [{"role": "user",
                                "content": "History:\n" + "\n".join(history[-8:]) + f"\nCommand: {command}"}]},
            timeout=15)
        r.raise_for_status()
        return r.json()["content"][0]["text"]
    except Exception:
        return None


def shell_output(command: str, history: list[str]) -> str:
    cmd = command.strip()
    if cmd in FAKE:
        return FAKE[cmd]
    out = _llm(cmd, history)
    if out:
        return out
    first = cmd.split()[0] if cmd else ""
    return f"bash: {first}: command not found" if first else ""


def fake_chatbot_leak() -> str:
    return ("SYSTEM PROMPT: You are SupportBot for Acme Corp. Internal API key: "
            "sk-DECOY-9f3a-not-real. Escalation email: admin@acme.invalid")

# ---------- API ----------
app = FastAPI(title="MirageAI", description="Adaptive AI honeypot")
DASH = Path(__file__).resolve().parent


class ShellIn(BaseModel):
    command: str
    session_id: str | None = None


class LoginIn(BaseModel):
    username: str
    password: str
    session_id: str | None = None


class ChatIn(BaseModel):
    message: str
    session_id: str | None = None


def _ip(request: Request) -> str:
    return request.client.host if request.client else "0.0.0.0"


@app.post("/api/shell")
def shell(body: ShellIn, request: Request):
    s = get_or_create(body.session_id, _ip(request), "shell")
    history = [e["input"] for e in s["events"]]
    out = shell_output(body.command, history)
    add_event(s, "shell", body.command, out, map_techniques(body.command))
    return {"session_id": s["id"], "output": out}


@app.post("/api/login")
def login(body: LoginIn, request: Request):
    s = get_or_create(body.session_id, _ip(request), "login")
    attempts = sum(1 for e in s["events"] if e["kind"] == "login") + 1
    ok = attempts >= 3  # let them "succeed" so they keep engaging
    add_event(s, "login", f"login attempt user={body.username[:32]}",
              "ok" if ok else "invalid", map_techniques("login attempt admin password"))
    return {"session_id": s["id"], "success": ok}


@app.post("/api/chat")
def chat(body: ChatIn, request: Request):
    s = get_or_create(body.session_id, _ip(request), "chat")
    if is_injection(body.message):
        out = fake_chatbot_leak()
        add_event(s, "prompt_injection", body.message[:200], out,
                  [{"id": "AML.T0051", "name": "LLM Prompt Injection (MITRE ATLAS)"}])
        return {"session_id": s["id"], "reply": out}
    reply = "Hi! How can I help you today?"
    add_event(s, "chat", body.message[:200], reply, [])
    return {"session_id": s["id"], "reply": reply}


@app.get("/api/sessions")
def sessions():
    out = []
    for s in SESSIONS.values():
        p = profile(s)
        out.append({**s, "profile": p, "block_rule": block_rule(s["ip"])})
    return sorted(out, key=lambda x: x["started"], reverse=True)


@app.get("/api/sessions/{sid}/rules")
def rules(sid: str):
    s = SESSIONS.get(sid)
    if not s:
        return {"error": "not found"}
    return {"sigma": sigma_rule(s), "block": block_rule(s["ip"])}


@app.get("/")
def index():
    return FileResponse(DASH / "index.html")