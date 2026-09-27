#!/usr/bin/env python3
"""
wg-dashboard : zero-dependency WireGuard traffic monitor + web dashboard.

Parses `wg show all dump` on an interval, keeps rolling history in SQLite,
and serves a live web UI (per-peer rx/tx totals, live throughput, handshake
age, endpoint IP) plus a Prometheus-compatible /metrics endpoint.

Only Python 3 stdlib is used. Run as root (or grant CAP_NET_ADMIN).

Usage:
    sudo python3 wg_dashboard.py --port 8080 --interval 5
    sudo python3 wg_dashboard.py --names /etc/wireguard/peers.txt

Optional peer name file, one per line:   <pubkey>=<friendly name>
"""

import argparse
import html
import json
import os
import sqlite3
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("WG_DASH_DB", "/var/lib/wg-dashboard/history.db")
STALE_AFTER = 180  # seconds without handshake => peer considered offline

# ---------------------------------------------------------------- collection

def run_wg_dump():
    """Return raw lines of `wg show all dump`."""
    out = subprocess.run(
        ["wg", "show", "all", "dump"],
        capture_output=True, text=True, check=True
    ).stdout
    return [l for l in out.splitlines() if l.strip()]


def parse_dump(lines):
    """
    Interface line: iface  privkey pubkey listen-port fwmark
    Peer line:      iface  pubkey  psk endpoint allowed-ips handshake rx tx keepalive
    """
    peers = []
    for line in lines:
        f = line.split("\t")
        if len(f) < 9:
            continue  # interface header line
        peers.append({
            "interface": f[0],
            "public_key": f[1],
            "endpoint": f[3] if f[3] != "(none)" else "",
            "allowed_ips": f[4],
            "last_handshake": int(f[5]),
            "rx_bytes": int(f[6]),
            "tx_bytes": int(f[7]),
        })
    return peers


def load_names(path):
    """
    Parse 'pubkey=Friendly Name' lines.

    WireGuard base64 keys are always 44 chars and end in '=', so splitting
    on the first '=' would swallow the key's own padding. Take the key as a
    fixed 44-char prefix, then skip an optional '=' or ':' separator.
    """
    names = {}
    if not path or not os.path.exists(path):
        return names
    for raw in open(path):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) >= 45 and line[43] == "=":
            key, rest = line[:44], line[44:]
        elif "=" in line:                    # fallback for odd/short keys
            key, rest = line.split("=", 1)
        else:
            continue
        name = rest.strip().lstrip("=:").strip()
        if key and name:
            names[key] = name
    return names


# ------------------------------------------------------------------- storage

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.execute("""CREATE TABLE IF NOT EXISTS samples(
        ts INTEGER, iface TEXT, pubkey TEXT,
        rx INTEGER, tx INTEGER, rx_rate REAL, tx_rate REAL)""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ts ON samples(ts)")
    con.commit()
    return con


class Collector(threading.Thread):
    """Polls wg, computes per-peer byte rates, persists samples."""

    daemon = True

    def __init__(self, interval, names, retention_hours):
        super().__init__()
        self.interval = interval
        self.names = names
        self.retention = retention_hours * 3600
        self.con = init_db()
        self.lock = threading.Lock()
        self.state = {}      # pubkey -> latest enriched peer dict
        self.prev = {}       # pubkey -> (ts, rx, tx)
        self.error = None

    def run(self):
        while True:
            try:
                self.collect()
                self.error = None
            except Exception as exc:                      # keep the UI alive
                self.error = str(exc)
            time.sleep(self.interval)

    def collect(self):
        now = int(time.time())
        peers = parse_dump(run_wg_dump())
        rows, snapshot = [], {}

        for p in peers:
            key = p["public_key"]
            prev = self.prev.get(key)
            rx_rate = tx_rate = 0.0
            if prev:
                dt = now - prev[0]
                if dt > 0:
                    # counters only reset on peer/interface restart -> clamp
                    rx_rate = max(0, p["rx_bytes"] - prev[1]) / dt
                    tx_rate = max(0, p["tx_bytes"] - prev[2]) / dt
            self.prev[key] = (now, p["rx_bytes"], p["tx_bytes"])

            p["name"] = self.names.get(key, key[:12] + "...")
            p["rx_rate"] = rx_rate
            p["tx_rate"] = tx_rate
            p["handshake_age"] = now - p["last_handshake"] if p["last_handshake"] else -1
            p["online"] = 0 <= p["handshake_age"] <= STALE_AFTER
            snapshot[key] = p
            rows.append((now, p["interface"], key, p["rx_bytes"], p["tx_bytes"],
                         rx_rate, tx_rate))

        with self.lock:
            self.state = snapshot
        self.con.executemany(
            "INSERT INTO samples VALUES (?,?,?,?,?,?,?)", rows)
        self.con.execute("DELETE FROM samples WHERE ts < ?", (now - self.retention,))
        self.con.commit()

    def current(self):
        with self.lock:
            return list(self.state.values())

    def history(self, minutes=60):
        since = int(time.time()) - minutes * 60
        cur = self.con.execute(
            "SELECT ts, SUM(rx_rate), SUM(tx_rate) FROM samples "
            "WHERE ts >= ? GROUP BY ts ORDER BY ts", (since,))
        return [{"ts": r[0], "rx": r[1], "tx": r[2]} for r in cur.fetchall()]


# ----------------------------------------------------------------- web layer

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>WireGuard Monitor</title>
<style>
 body{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#0f1420;color:#e6e9ef}
 header{padding:16px 24px;background:#161d2e;border-bottom:1px solid #263049}
 h1{font-size:18px;margin:0}
 .wrap{padding:20px 24px}
 .cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}
 .card{background:#161d2e;border:1px solid #263049;border-radius:8px;padding:14px 18px;min-width:150px}
 .card .v{font-size:24px;font-weight:600}
 .card .l{font-size:12px;color:#8f9bb3;text-transform:uppercase;letter-spacing:.5px}
 table{width:100%;border-collapse:collapse;background:#161d2e;border-radius:8px;overflow:hidden}
 th,td{padding:10px 14px;text-align:left;font-size:14px;border-bottom:1px solid #263049}
 th{background:#1c2538;color:#8f9bb3;font-size:12px;text-transform:uppercase}
 .up{color:#3ddc84}.down{color:#ff6b6b}
 canvas{background:#161d2e;border:1px solid #263049;border-radius:8px;margin-bottom:20px}
 .err{background:#4a1d1d;padding:10px 14px;border-radius:6px;margin-bottom:14px}
</style></head><body>
<header><h1>WireGuard Traffic Monitor</h1></header>
<div class="wrap">
 <div id="err"></div>
 <div class="cards" id="cards"></div>
 <canvas id="chart" width="1200" height="220"></canvas>
 <table><thead><tr>
  <th>Peer</th><th>Interface</th><th>Allowed IPs</th><th>Endpoint</th>
  <th>Status</th><th>Last handshake</th><th>Down (rx)</th><th>Up (tx)</th>
  <th>Total rx</th><th>Total tx</th></tr></thead>
 <tbody id="rows"></tbody></table>
</div>
<script>
const fmtB=b=>{const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(1)+' '+u[i]};
const fmtR=b=>fmtB(b)+'/s';
const fmtAge=s=>s<0?'never':s<60?s+'s ago':s<3600?Math.floor(s/60)+'m ago':Math.floor(s/3600)+'h ago';
async function tick(){
 const d=await (await fetch('/api/status')).json();
 document.getElementById('err').innerHTML = d.error? '<div class="err">collector error: '+d.error+'</div>':'';
 const on=d.peers.filter(p=>p.online).length;
 const rx=d.peers.reduce((a,p)=>a+p.rx_rate,0), tx=d.peers.reduce((a,p)=>a+p.tx_rate,0);
 const trx=d.peers.reduce((a,p)=>a+p.rx_bytes,0), ttx=d.peers.reduce((a,p)=>a+p.tx_bytes,0);
 document.getElementById('cards').innerHTML=[
  ['Peers online',on+' / '+d.peers.length],['Download',fmtR(rx)],['Upload',fmtR(tx)],
  ['Total rx',fmtB(trx)],['Total tx',fmtB(ttx)]
 ].map(c=>`<div class="card"><div class="l">${c[0]}</div><div class="v">${c[1]}</div></div>`).join('');
  document.getElementById('rows').innerHTML=d.peers.sort((a,b)=>
    (b.rx_rate+b.tx_rate)-(a.rx_rate+a.tx_rate)
 || (b.online?1:0)-(a.online?1:0)
 || (b.rx_bytes+b.tx_bytes)-(a.rx_bytes+a.tx_bytes)
 || a.name.localeCompare(b.name))
  .map(p=>`<tr><td>${p.name}</td><td>${p.interface}</td><td>${p.allowed_ips}</td><td>${p.endpoint||'-'}</td>
   <td class="${p.online?'up':'down'}">${p.online?'online':'offline'}</td><td>${fmtAge(p.handshake_age)}</td>
   <td>${fmtR(p.rx_rate)}</td><td>${fmtR(p.tx_rate)}</td><td>${fmtB(p.rx_bytes)}</td><td>${fmtB(p.tx_bytes)}</td></tr>`).join('');
 draw(await (await fetch('/api/history?minutes=60')).json());
}
function draw(h){
 const c=document.getElementById('chart'),x=c.getContext('2d');
 x.clearRect(0,0,c.width,c.height);
 if(!h.length)return;

 // Give the graph extra space for time labels
 const left=55, right=15, top=20, bottom=35;

 const max=Math.max(1,...h.map(p=>Math.max(p.rx,p.tx)));

 const px=(i)=>
   left + i/(h.length-1||1)*(c.width-left-right);

 const py=(v)=>
   c.height-bottom-v/max*(c.height-top-bottom);

 // X-axis
 x.strokeStyle='#263049';
 x.beginPath();
 x.moveTo(left,c.height-bottom);
 x.lineTo(c.width-right,c.height-bottom);
 x.stroke();

 // RX/TX lines
 [['rx','#4da3ff'],['tx','#3ddc84']].forEach(([k,col])=>{
   x.strokeStyle=col;
   x.lineWidth=2;
   x.beginPath();

   h.forEach((p,i)=>
     i
       ? x.lineTo(px(i),py(p[k]))
       : x.moveTo(px(i),py(p[k]))
   );

   x.stroke();
 });

 // Maximum throughput label
 x.fillStyle='#8f9bb3';
 x.font='12px sans-serif';
 x.fillText(fmtB(max)+'/s',6,16);

 // Legend
 x.fillStyle='#4da3ff';
 x.fillText('RX',c.width-70,16);

 x.fillStyle='#3ddc84';
 x.fillText('TX',c.width-35,16);

 // ----- TIME LABELS -----
 const numberOfLabels=6;

 x.fillStyle='#8f9bb3';
 x.font='11px sans-serif';
 x.textAlign='center';

 for(let n=0;n<numberOfLabels;n++){

   const index=Math.round(
     n*(h.length-1)/(numberOfLabels-1)
   );

   const p=h[index];

   if(!p) continue;

   const date=new Date(p.ts*1000);

   const label=date.toLocaleTimeString([],{
     hour:'2-digit',
     minute:'2-digit'
   });

   x.fillText(
     label,
     px(index),
     c.height-10
   );

   // Small tick mark
   x.strokeStyle='#263049';
   x.beginPath();
   x.moveTo(px(index),c.height-bottom);
   x.lineTo(px(index),c.height-bottom+5);
   x.stroke();
 }
}
tick();setInterval(tick,5000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    collector = None

    def _send(self, code, body, ctype):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?")[0]
        c = self.collector
        if path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif path == "/api/status":
            self._send(200, json.dumps({"peers": c.current(), "error": c.error}),
                       "application/json")
        elif path == "/api/history":
            q = self.path.split("minutes=")
            mins = int(q[1]) if len(q) > 1 and q[1].isdigit() else 60
            self._send(200, json.dumps(c.history(mins)), "application/json")
        elif path == "/metrics":
            self._send(200, self.prom(c.current()), "text/plain; version=0.0.4")
        else:
            self._send(404, "not found", "text/plain")

    @staticmethod
    def prom(peers):
        out = [
            "# TYPE wireguard_peer_received_bytes_total counter",
            "# TYPE wireguard_peer_sent_bytes_total counter",
            "# TYPE wireguard_peer_last_handshake_seconds gauge",
            "# TYPE wireguard_peer_online gauge",
        ]
        for p in peers:
            lbl = ('interface="%s",public_key="%s",name="%s",allowed_ips="%s"'
                   % (p["interface"], p["public_key"], p["name"], p["allowed_ips"]))
            out += [
                'wireguard_peer_received_bytes_total{%s} %d' % (lbl, p["rx_bytes"]),
                'wireguard_peer_sent_bytes_total{%s} %d' % (lbl, p["tx_bytes"]),
                'wireguard_peer_last_handshake_seconds{%s} %d' % (lbl, p["last_handshake"]),
                'wireguard_peer_online{%s} %d' % (lbl, int(p["online"])),
            ]
        return "\n".join(out) + "\n"

    def log_message(self, *a):
        pass  # silence per-request logging


def main():
    ap = argparse.ArgumentParser(description="WireGuard traffic dashboard")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--bind", default="127.0.0.1",
                    help="bind address (default loopback; put a proxy in front)")
    ap.add_argument("--interval", type=int, default=5, help="poll seconds")
    ap.add_argument("--names", help="file of 'pubkey=Friendly Name' lines")
    ap.add_argument("--retention-hours", type=int, default=48)
    args = ap.parse_args()

    col = Collector(args.interval, load_names(args.names), args.retention_hours)
    col.start()
    Handler.collector = col
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print("wg-dashboard on http://%s:%d  (metrics at /metrics)" % (args.bind, args.port))
    srv.serve_forever()


if __name__ == "__main__":
    main()
