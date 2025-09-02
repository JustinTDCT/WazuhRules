#!/usr/bin/env python3
import os, socket, time, json
import datetime as dt
from pymongo import MongoClient
from bson.objectid import ObjectId
from bson import json_util

# ---- Config via env ----
MONGO_URI   = os.getenv("MONGO_URI", "mongodb://127.0.0.1:27117/ace")
COLLS       = [c.strip() for c in os.getenv("COLLECTIONS","event,alarm").split(",") if c.strip()]
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "10.150.125.65")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "514"))
POLL_SECS   = float(os.getenv("POLL_SECS", "2.0"))
STATE_FILE  = os.getenv("STATE_FILE", "/var/lib/unifi-to-wazuh/state.json")
PROGRAM     = os.getenv("PROGRAM", "unifi-event")
FAC_PRI     = int(os.getenv("PRI", "134"))  # <134>=local0.info
DEBUG       = os.getenv("DEBUG","0") == "1"
HOSTNAME    = os.uname().nodename

def now_utc_rfc3339():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")

def default_cut():
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    return {"oid": str(ObjectId.from_datetime(t)), "time": int(t.timestamp())}

def load_state():
    try:
        with open(STATE_FILE,"r") as f:
            s = json.load(f)
        for c in COLLS:
            s.setdefault(c, default_cut())
        return s
    except Exception:
        return {c: default_cut() for c in COLLS}

def save_state(s):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp,"w") as f:
        json.dump(s,f)
    os.replace(tmp, STATE_FILE)

def to_syslog(payload_json):
    return f"<{FAC_PRI}>1 {now_utc_rfc3339()} {HOSTNAME} {PROGRAM} - - - {payload_json}"

def normalize(doc: dict) -> dict:
    out = dict(doc)
    out["_controller_host"] = HOSTNAME
    for k in ("site_id","ap","sw","user","mac","hostname","ip","ssid","radio",
              "channel","subsystem","key","category","msg","event_type"):
        if k in doc:
            out[f"unifi_{k}"] = doc[k]
    return out

def main():
    client = MongoClient(MONGO_URI)
    db = client.get_default_database()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    state = load_state()

    while True:
        any_sent = 0
        for name in COLLS:
            st = state.get(name, default_cut())
            last_oid  = ObjectId(st.get("oid", default_cut()["oid"]))
            last_time = int(st.get("time", default_cut()["time"]))

            coll = db[name]
            # Prefer numeric "time" if present; also guard with _id
            q = {"$or": [{"time": {"$gt": last_time}}, {"_id": {"$gt": last_oid}}]}
            docs = list(coll.find(q).sort("_id", 1).limit(1000))
            if DEBUG:
                print(f"[DBG] {name}: since oid={str(last_oid)} time={last_time} -> {len(docs)} docs")

            for doc in docs:
                doc["_collection"] = name
                payload = json.dumps(normalize(doc), default=json_util.default, separators=(",",":"))
                sock.sendto(to_syslog(payload).encode(), (SYSLOG_HOST, SYSLOG_PORT))
                # advance per-collection watermark
                st["oid"] = str(doc["_id"])
                if isinstance(doc.get("time"), (int, float)):
                    st["time"] = int(doc["time"])
                any_sent += 1

            state[name] = st

        if any_sent:
            save_state(state)
            if DEBUG:
                print(f"[DBG] saved state, sent={any_sent}")
        else:
            time.sleep(POLL_SECS)

if __name__ == "__main__":
    main()
