  GNU nano 7.2                                                                             /opt/unifi-to-wazuh/unifi_events_to_wazuh.py                                                                                      
#!/usr/bin/env python3
import os, socket, time, json
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson import json_util


# ---- Config via env (override as needed) ----
MONGO_URI   = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27117/ace")  # self-hosted UniFi default
COLLS       = [c.strip() for c in os.getenv("COLLECTIONS","event,alarm").split(",")]
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "10.150.125.65")  # your Wazuh/syslog collector
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
POLL_SECS   = float(os.getenv("POLL_SECS", "2.0"))
STATE_FILE  = os.getenv("STATE_FILE", "/var/lib/unifi-to-wazuh/last_id.txt")
PROGRAM     = os.getenv("PROGRAM", "unifi-event")
FAC_PRI     = int(os.getenv("PRI", "134"))  # <134>=local0.info

HOSTNAME = os.uname().nodename

def ts():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

def now_rfc3339():
    # RFC3339 UTC (no microseconds), e.g. 2025-09-02T16:57:00Z
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def load_last_id():
    try:
        with open(STATE_FILE, "r") as f:
            return ObjectId(f.read().strip())
    except Exception:
        # start 24h back if no state
        return ObjectId.from_datetime(datetime.now(timezone.utc) - timedelta(days=1))

def save_last_id(oid):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        f.write(str(oid))

def to_syslog(payload_json):
    return f"<{FAC_PRI}>1 {ts()} {HOSTNAME} {PROGRAM} - - - {payload_json}"

def normalize(doc):
    """Light normalization so Wazuh rules can key off stable fields."""
    out = dict(doc)  # bson still OK, we'll json_util it later
    out["_controller_host"] = HOSTNAME
    # Common UniFi fields across event/alarm docs we often care about:
    # 'site_id','ap','sw','usg','iface','radio','ssid','user','mac','hostname',
                                                                                                      [ Read 81 lines ]
^G Help          ^O Write Out     ^W Where Is      ^K Cut           ^T Execute       ^C Location      M-U Undo         M-A Set Mark     M-] To Bracket   M-Q Previous     ^B Back          ^◂ Prev Word     ^A Home
^X Exit          ^R Read File     ^\ Replace       ^U Paste         ^J Justify       ^/ Go To Line    M-E Redo         M-6 Copy         ^Q Where Was     M-W Next         ^F Forward       ^▸ Next Word     ^E End
