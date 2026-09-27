#!/usr/bin/env python3
import argparse, json, os, sqlite3, subprocess, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DB_PATH=os.environ.get('WG_DASH_DB','/var/lib/wg-dashboard/history.db')
STALE_AFTER=180

def load_names(path):
    names={}
    if not path or not os.path.exists(path):
        print(f'names file not found: {path}',flush=True); return names
    with open(path,encoding='utf-8-sig') as f:
        for raw in f:
            line=raw.strip()
            if not line or line.startswith('#'): continue
            if len(line)>=45 and line[43]=='=': key,rest=line[:44],line[44:]
            elif '=' in line: key,rest=line.split('=',1)
            else: continue
            name=rest.strip().lstrip('=:').strip()
            if key and name: names[key]=name
    print(f'loaded {len(names)} peer names from {path}',flush=True)
    return names

def wg_peers():
    out=subprocess.run(['wg','show','all','dump'],capture_output=True,text=True,check=True).stdout
    peers=[]
    for line in out.splitlines():
        f=line.split('\t')
        if len(f)<9: continue
        peers.append({'interface':f[0],'public_key':f[1],'endpoint':'' if f[3]=='(none)' else f[3],
          'allowed_ips':f[4],'last_handshake':int(f[5]),'rx_bytes':int(f[6]),'tx_bytes':int(f[7])})
    return peers

def init_db():
    os.makedirs(os.path.dirname(DB_PATH),exist_ok=True)
    c=sqlite3.connect(DB_PATH,check_same_thread=False)
    c.execute('CREATE TABLE IF NOT EXISTS samples(ts INTEGER,iface TEXT,pubkey TEXT,rx INTEGER,tx INTEGER,rx_rate REAL,tx_rate REAL)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_ts ON samples(ts)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_peer_ts ON samples(pubkey,ts)')
    c.commit(); return c

class Collector(threading.Thread):
    daemon=True
    def __init__(self,interval,names_file,retention):
        super().__init__(); self.interval=interval; self.names_file=names_file
        self.names=load_names(names_file); self.names_mtime=self.mtime(); self.retention=retention*3600
        self.db=init_db(); self.lock=threading.Lock(); self.state={}; self.prev={}; self.error=None
    def mtime(self):
        try:return os.path.getmtime(self.names_file) if self.names_file else None
        except OSError:return None
    def run(self):
        while True:
            try:self.collect(); self.error=None
            except Exception as e:self.error=str(e); print('collector error:',e,flush=True)
            time.sleep(self.interval)
    def collect(self):
        mt=self.mtime()
        if mt!=self.names_mtime:self.names=load_names(self.names_file);self.names_mtime=mt
        now=int(time.time()); snap={}; rows=[]
        for p in wg_peers():
            k=p['public_key']; old=self.prev.get(k); rr=tr=0.0
            if old and now>old[0]:
                rr=max(0,p['rx_bytes']-old[1])/(now-old[0]); tr=max(0,p['tx_bytes']-old[2])/(now-old[0])
            self.prev[k]=(now,p['rx_bytes'],p['tx_bytes'])
            p.update(name=self.names.get(k,k[:12]+'...'),rx_rate=rr,tx_rate=tr)
            p['handshake_age']=now-p['last_handshake'] if p['last_handshake'] else -1
            p['online']=0<=p['handshake_age']<=STALE_AFTER; snap[k]=p
            rows.append((now,p['interface'],k,p['rx_bytes'],p['tx_bytes'],rr,tr))
        with self.lock:self.state=snap
        self.db.executemany('INSERT INTO samples VALUES(?,?,?,?,?,?,?)',rows)
        self.db.execute('DELETE FROM samples WHERE ts<?',(now-self.retention,)); self.db.commit()
    def current(self):
        with self.lock:return list(self.state.values())
    def history(self,minutes,per_peer=False):
        since=int(time.time())-minutes*60
        if per_peer:
            q=self.db.execute('SELECT ts,pubkey,rx_rate,tx_rate FROM samples WHERE ts>=? ORDER BY ts,pubkey',(since,))
            return [{'ts':r[0],'pubkey':r[1],'rx':r[2] or 0,'tx':r[3] or 0} for r in q]
        q=self.db.execute('SELECT ts,SUM(rx_rate),SUM(tx_rate) FROM samples WHERE ts>=? GROUP BY ts ORDER BY ts',(since,))
        return [{'ts':r[0],'rx':r[1] or 0,'tx':r[2] or 0} for r in q]

    def daily_stats(self, days=30):
        # Calculate traffic from positive changes in cumulative WireGuard counters.
        # Buckets use the Ubuntu server's local calendar date.
        since = int(time.time()) - (days + 1) * 86400
        q = self.db.execute(
            'SELECT ts,pubkey,rx,tx FROM samples WHERE ts>=? ORDER BY pubkey,ts',
            (since,))
        totals = {}
        previous = {}
        names = {p['public_key']: p['name'] for p in self.current()}
        for ts, key, rx, tx in q:
            old = previous.get(key)
            previous[key] = (rx, tx)
            if old is None:
                continue
            drx = max(0, rx - old[0])
            dtx = max(0, tx - old[1])
            day = time.strftime('%Y-%m-%d', time.localtime(ts))
            bucket = totals.setdefault(day, {})
            peer = bucket.setdefault(key, {'rx': 0, 'tx': 0})
            peer['rx'] += drx
            peer['tx'] += dtx
        result = []
        for day in sorted(totals)[-days:]:
            peers = []
            for key, values in totals[day].items():
                peers.append({'pubkey': key, 'name': names.get(key, key[:12] + '...'),
                              'rx': values['rx'], 'tx': values['tx'],
                              'total': values['rx'] + values['tx']})
            peers.sort(key=lambda x: x['total'], reverse=True)
            result.append({'date': day,
                           'rx': sum(x['rx'] for x in peers),
                           'tx': sum(x['tx'] for x in peers),
                           'total': sum(x['total'] for x in peers),
                           'peers': peers})
        return result

PAGE=r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>WireGuard Monitor</title><style>
*{box-sizing:border-box}body{font-family:Segoe UI,system-ui;margin:0;background:#0f1420;color:#e6e9ef}header{padding:16px 24px;background:#161d2e;border-bottom:1px solid #263049}h1{font-size:19px;margin:0}.wrap{padding:20px 24px}.cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}.card,.panel{background:#161d2e;border:1px solid #263049;border-radius:9px}.card{padding:14px 18px;min-width:150px}.v{font-size:24px;font-weight:600}.l{font-size:12px;color:#8f9bb3;text-transform:uppercase}.panel{padding:14px;margin-bottom:20px}.title{font-size:14px;font-weight:600;margin-bottom:10px}canvas{width:100%;height:250px;display:block}.legend{display:flex;gap:8px 15px;flex-wrap:wrap;font-size:12px;color:#b9c2d3;margin-bottom:8px}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:7px}.table{overflow-x:auto}table{width:100%;border-collapse:collapse;background:#161d2e}th,td{padding:10px 14px;text-align:left;border-bottom:1px solid #263049;white-space:nowrap;font-size:14px}th{background:#1c2538;color:#8f9bb3;font-size:12px}.up{color:#3ddc84}.down{color:#ff6b6b}.err{background:#4a1d1d;padding:10px;margin-bottom:14px}.tabs{display:flex;gap:8px;margin-bottom:18px}.tab{border:1px solid #34415d;background:#161d2e;color:#b9c2d3;padding:9px 16px;border-radius:7px;cursor:pointer}.tab.active{background:#2878d0;color:white;border-color:#2878d0}.view{display:none}.view.active{display:block}.daily-controls{display:flex;align-items:center;gap:12px;margin-bottom:14px}.daily-controls select{background:#161d2e;color:#e6e9ef;border:1px solid #34415d;padding:7px;border-radius:6px}</style></head><body><header><h1>WireGuard Traffic Monitor</h1></header><div class="wrap"><div id="err"></div><div class="tabs"><button class="tab active" data-view="liveView">Live</button><button class="tab" data-view="dailyView">Daily Usage</button></div><section id="liveView" class="view active"><div class="cards" id="cards"></div><div class="panel"><div class="title">Overall VPN Throughput</div><canvas id="overall"></canvas></div><div class="panel"><div class="title">Traffic by Peer (RX + TX)</div><div class="legend" id="legend"></div><canvas id="peers"></canvas></div><div class="table"><table><thead><tr><th>Peer</th><th>Interface</th><th>Allowed IPs</th><th>Endpoint</th><th>Status</th><th>Last handshake</th><th>Down</th><th>Up</th><th>Total RX</th><th>Total TX</th></tr></thead><tbody id="rows"></tbody></table></div></section><section id="dailyView" class="view"><div class="daily-controls"><label>Selected day <select id="daySelect"></select></label></div><div class="cards" id="dailyCards"></div><div class="panel"><div class="title">Daily Total Traffic</div><canvas id="dailyChart"></canvas></div><div class="table"><table><thead><tr><th>Peer</th><th>Download (RX)</th><th>Upload (TX)</th><th>Total</th><th>Share</th></tr></thead><tbody id="dailyRows"></tbody></table></div></section></div><script>
const C=['#4da3ff','#3ddc84','#ff9f43','#a55eea','#ff6b6b','#26de81','#fed330','#45aaf2','#fc5c65','#2bcbba','#778ca3','#8854d0','#e84393','#00cec9','#fdcb6e','#74b9ff'];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=b=>{let u=['B','KB','MB','GB','TB'],i=0;b=+b||0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(1)+' '+u[i]},rate=b=>fmt(b)+'/s';
const age=s=>s<0?'never':s<60?s+'s ago':s<3600?Math.floor(s/60)+'m ago':Math.floor(s/3600)+'h ago';
function color(k){let h=0;for(let i=0;i<k.length;i++){h=((h<<5)-h)+k.charCodeAt(i);h|=0}return C[Math.abs(h)%C.length]}
function canvasSetup(id){let c=document.getElementById(id),r=devicePixelRatio||1,w=Math.max(300,c.clientWidth),h=Math.max(180,c.clientHeight);c.width=w*r;c.height=h*r;let x=c.getContext('2d');x.setTransform(r,0,0,r,0,0);return{x,w,h}}
function label(ts){return new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}
function axes(x,w,h,max,t0,t1){let a={l:62,r:14,t:16,b:35};x.font='11px Segoe UI';x.strokeStyle='#263049';x.fillStyle='#8f9bb3';for(let i=0;i<=4;i++){let y=a.t+i*(h-a.t-a.b)/4,v=max*(4-i)/4;x.textAlign='right';x.fillText(rate(v),a.l-7,y+4);x.beginPath();x.moveTo(a.l,y);x.lineTo(w-a.r,y);x.stroke()}for(let i=0;i<6;i++){let q=i/5,xx=a.l+q*(w-a.l-a.r);x.textAlign='center';x.fillText(label(t0+(t1-t0)*q),xx,h-10)}return a}
function overall(data){let{x,w,h}=canvasSetup('overall');x.clearRect(0,0,w,h);if(!data.length)return;let max=Math.max(1,...data.flatMap(p=>[p.rx,p.tx])),a=axes(x,w,h,max,data[0].ts,data.at(-1).ts),px=i=>a.l+i/(data.length-1||1)*(w-a.l-a.r),py=v=>h-a.b-v/max*(h-a.t-a.b);[['rx','#4da3ff'],['tx','#3ddc84']].forEach(([k,c])=>{x.strokeStyle=c;x.lineWidth=2;x.beginPath();data.forEach((p,i)=>i?x.lineTo(px(i),py(p[k])):x.moveTo(px(i),py(p[k])));x.stroke()})}
function peerGraph(data,peers){let{x,w,h}=canvasSetup('peers');x.clearRect(0,0,w,h);let names=Object.fromEntries(peers.map(p=>[p.public_key,p.name])),g={};data.forEach(p=>(g[p.pubkey]??=[]).push({ts:p.ts,v:p.rx+p.tx}));let active=Object.entries(g).filter(([,v])=>v.some(p=>p.v>0));document.getElementById('legend').innerHTML=active.length?active.map(([k])=>`<span><i class="dot" style="background:${color(k)}"></i>${esc(names[k]||k.slice(0,12)+'...')}</span>`).join(''):'No peer traffic in this period';if(!active.length)return;let all=active.flatMap(([,v])=>v),t0=Math.min(...all.map(p=>p.ts)),t1=Math.max(...all.map(p=>p.ts)),max=Math.max(1,...all.map(p=>p.v)),a=axes(x,w,h,max,t0,t1),px=t=>a.l+(t-t0)/(t1-t0||1)*(w-a.l-a.r),py=v=>h-a.b-v/max*(h-a.t-a.b);active.forEach(([k,v])=>{x.strokeStyle=color(k);x.lineWidth=2;x.beginPath();v.forEach((p,i)=>i?x.lineTo(px(p.ts),py(p.v)):x.moveTo(px(p.ts),py(p.v)));x.stroke()})}

let D=[];
function drawDaily(data) {
    let {x,w,h} = canvasSetup('dailyChart');

    x.clearRect(0,0,w,h);

    if (!data.length)
        return;

    let max = Math.max(1, ...data.map(d => d.total));

    let a = {
        l: 62,
        r: 14,
        t: 16,
        b: 45
    };

    x.font = '11px Segoe UI';

    // Y axis
    for (let i = 0; i <= 4; i++) {

        let y = a.t + i * (h-a.t-a.b) / 4;
        let v = max * (4-i) / 4;

        x.fillStyle = '#8f9bb3';
        x.textAlign = 'right';

        x.fillText(
            fmt(v),
            a.l - 7,
            y + 4
        );

        x.strokeStyle = '#263049';

        x.beginPath();
        x.moveTo(a.l,y);
        x.lineTo(w-a.r,y);
        x.stroke();
    }

    let space = (w-a.l-a.r) / data.length;

    let bw = Math.max(
        3,
        space * 0.62
    );

    data.forEach((d,i) => {

        let xx =
            a.l +
            i * space +
            (space-bw)/2;

        let rxHeight =
            d.rx/max *
            (h-a.t-a.b);

        let txHeight =
            d.tx/max *
            (h-a.t-a.b);

        // RX
        x.fillStyle = '#4da3ff';

        x.fillRect(
            xx,
            h-a.b-rxHeight,
            bw,
            rxHeight
        );

        // TX
        x.fillStyle = '#3ddc84';

        x.fillRect(
            xx,
            h-a.b-rxHeight-txHeight,
            bw,
            txHeight
        );

        // -----------------------------
        // X AXIS DATE
        // -----------------------------

        let date = new Date(
            d.date + 'T00:00:00'
        );

        let dateLabel =
            date.toLocaleDateString(
                undefined,
                {
                    month: 'short',
                    day: 'numeric'
                }
            );

        x.fillStyle = '#8f9bb3';

        x.font =
            '11px Segoe UI';

        x.textAlign =
            'center';

        x.fillText(
            dateLabel,
            xx + bw/2,
            h - 12
        );
    });
}
function renderDay(date){let d=D.find(x=>x.date===date);if(!d)return;document.getElementById('dailyCards').innerHTML=[['Date',d.date],['Total traffic',fmt(d.total)],['Download',fmt(d.rx)],['Upload',fmt(d.tx)],['Active peers',d.peers.filter(p=>p.total>0).length]].map(z=>`<div class="card"><div class="l">${z[0]}</div><div class="v">${z[1]}</div></div>`).join('');document.getElementById('dailyRows').innerHTML=d.peers.map(p=>`<tr><td><i class="dot" style="background:${color(p.pubkey)}"></i>${esc(p.name)}</td><td>${fmt(p.rx)}</td><td>${fmt(p.tx)}</td><td>${fmt(p.total)}</td><td>${d.total?((p.total/d.total)*100).toFixed(1):'0.0'}%</td></tr>`).join('')}
async function loadDaily(){let r=await fetch('/api/daily?days=30');D=await r.json();let sel=document.getElementById('daySelect'),chosen=sel.value;sel.innerHTML=[...D].reverse().map(d=>`<option value="${d.date}">${d.date}</option>`).join('');if(chosen&&D.some(d=>d.date===chosen))sel.value=chosen;drawDaily(D);if(D.length)renderDay(sel.value||D.at(-1).date)}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.view').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.getElementById(b.dataset.view).classList.add('active');if(b.dataset.view==='dailyView')loadDaily()});
document.addEventListener('change',e=>{if(e.target.id==='daySelect')renderDay(e.target.value)});

let O=[],P=[],S=[];async function tick(){try{let[a,b,c]=await Promise.all([fetch('/api/status'),fetch('/api/history?minutes=60'),fetch('/api/peer-history?minutes=60')]);let s=await a.json();O=await b.json();P=await c.json();S=s.peers;document.getElementById('err').innerHTML=s.error?`<div class="err">${esc(s.error)}</div>`:'';let on=S.filter(p=>p.online).length,rx=S.reduce((a,p)=>a+p.rx_rate,0),tx=S.reduce((a,p)=>a+p.tx_rate,0),rt=S.reduce((a,p)=>a+p.rx_bytes,0),tt=S.reduce((a,p)=>a+p.tx_bytes,0);document.getElementById('cards').innerHTML=[['Peers online',on+' / '+S.length],['Download',rate(rx)],['Upload',rate(tx)],['Total RX',fmt(rt)],['Total TX',fmt(tt)]].map(z=>`<div class="card"><div class="l">${z[0]}</div><div class="v">${z[1]}</div></div>`).join('');let sorted=[...S].sort((a,b)=>(b.rx_rate+b.tx_rate)-(a.rx_rate+a.tx_rate)||+b.online-+a.online||(b.rx_bytes+b.tx_bytes)-(a.rx_bytes+a.tx_bytes)||a.name.localeCompare(b.name));document.getElementById('rows').innerHTML=sorted.map(p=>`<tr><td><i class="dot" style="background:${color(p.public_key)}"></i>${esc(p.name)}</td><td>${esc(p.interface)}</td><td>${esc(p.allowed_ips)}</td><td>${esc(p.endpoint||'-')}</td><td class="${p.online?'up':'down'}">${p.online?'online':'offline'}</td><td>${age(p.handshake_age)}</td><td>${rate(p.rx_rate)}</td><td>${rate(p.tx_rate)}</td><td>${fmt(p.rx_bytes)}</td><td>${fmt(p.tx_bytes)}</td></tr>`).join('');overall(O);peerGraph(P,S)}catch(e){document.getElementById('err').innerHTML=`<div class="err">${esc(e)}</div>`}}
let z;addEventListener('resize',()=>{clearTimeout(z);z=setTimeout(()=>{overall(O);peerGraph(P,S)},150)});tick();setInterval(tick,5000);
</script></body></html>'''

class Handler(BaseHTTPRequestHandler):
    collector=None
    def sendit(self,code,body,ctype):
        data=body.encode();self.send_response(code);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(data)
    def minutes(self):
        try:return max(1,min(int(parse_qs(urlparse(self.path).query).get('minutes',['60'])[0]),2880))
        except:return 60
    def do_GET(self):
        p=urlparse(self.path).path;c=self.collector
        if p=='/':self.sendit(200,PAGE,'text/html; charset=utf-8')
        elif p=='/api/status':self.sendit(200,json.dumps({'peers':c.current(),'error':c.error}),'application/json')
        elif p=='/api/history':self.sendit(200,json.dumps(c.history(self.minutes())),'application/json')
        elif p=='/api/peer-history':self.sendit(200,json.dumps(c.history(self.minutes(),True)),'application/json')
        elif p=='/api/daily':
            try: days=max(1,min(int(parse_qs(urlparse(self.path).query).get('days',['30'])[0]),365))
            except ValueError: days=30
            self.sendit(200,json.dumps(c.daily_stats(days)),'application/json')
        else:self.sendit(404,'not found','text/plain')
    def log_message(self,*args):pass

def main():
    a=argparse.ArgumentParser();a.add_argument('--bind',default='127.0.0.1');a.add_argument('--port',type=int,default=8080);a.add_argument('--interval',type=int,default=5);a.add_argument('--names');a.add_argument('--retention-hours',type=int,default=720);x=a.parse_args()
    c=Collector(x.interval,x.names,x.retention_hours);c.start();Handler.collector=c
    print(f'wg-dashboard listening on http://{x.bind}:{x.port}',flush=True);ThreadingHTTPServer((x.bind,x.port),Handler).serve_forever()
if __name__=='__main__':main()
