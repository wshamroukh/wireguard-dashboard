#!/usr/bin/env python3

import argparse
import json
import os
import sqlite3
import subprocess
import threading
import time

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


DB_PATH = os.environ.get(
    "WG_DASH_DB",
    "/var/lib/wg-dashboard/history.db",
)

STALE_AFTER = 180


# ============================================================================
# Peer names
# ============================================================================

def load_names(path):
    names = {}

    if not path or not os.path.exists(path):
        print(
            f"names file not found: {path}",
            flush=True,
        )
        return names

    # utf-8-sig also handles a possible BOM at the beginning of the file.
    with open(path, encoding="utf-8-sig") as file:
        for raw in file:
            line = raw.strip()

            if not line or line.startswith("#"):
                continue

            # WireGuard public keys are normally 44-character base64 strings
            # ending with "=".
            if len(line) >= 45 and line[43] == "=":
                key = line[:44]
                rest = line[44:]

            elif "=" in line:
                key, rest = line.split("=", 1)

            else:
                continue

            name = rest.strip().lstrip("=:").strip()

            if key and name:
                names[key] = name

    print(
        f"loaded {len(names)} peer names from {path}",
        flush=True,
    )

    return names


# ============================================================================
# WireGuard
# ============================================================================

def wg_peers():
    result = subprocess.run(
        [
            "wg",
            "show",
            "all",
            "dump",
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    peers = []

    for line in result.stdout.splitlines():
        fields = line.split("\t")

        # Ignore the WireGuard interface/header row.
        if len(fields) < 9:
            continue

        peers.append(
            {
                "interface": fields[0],
                "public_key": fields[1],
                "endpoint": (
                    ""
                    if fields[3] == "(none)"
                    else fields[3]
                ),
                "allowed_ips": fields[4],
                "last_handshake": int(fields[5]),
                "rx_bytes": int(fields[6]),
                "tx_bytes": int(fields[7]),
            }
        )

    return peers


# ============================================================================
# SQLite
# ============================================================================

def init_db():
    database_directory = os.path.dirname(
        DB_PATH
    )

    os.makedirs(
        database_directory,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
        timeout=30,
    )

    # Improve read/write concurrency.
    connection.execute(
        "PRAGMA journal_mode = WAL"
    )

    connection.execute(
        "PRAGMA synchronous = NORMAL"
    )

    connection.execute(
        "PRAGMA busy_timeout = 30000"
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS samples (
            ts INTEGER,
            iface TEXT,
            pubkey TEXT,
            rx INTEGER,
            tx INTEGER,
            rx_rate REAL,
            tx_rate REAL
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ts
        ON samples(ts)
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_peer_ts
        ON samples(pubkey, ts)
        """
    )

    # Compact daily aggregation table.
    #
    # Each peer has one row per day instead of one row every
    # five seconds.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS daily_usage (
            date TEXT NOT NULL,
            pubkey TEXT NOT NULL,
            rx INTEGER NOT NULL DEFAULT 0,
            tx INTEGER NOT NULL DEFAULT 0,

            PRIMARY KEY (
                date,
                pubkey
            )
        )
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_daily_usage_date
        ON daily_usage(date)
        """
    )

    connection.commit()

    return connection


# ============================================================================
# Collector
# ============================================================================

class Collector(threading.Thread):
    daemon = True

    def __init__(
        self,
        interval,
        names_file,
        retention,
    ):
        super().__init__()

        self.interval = interval
        self.names_file = names_file
        self.names = load_names(names_file)
        self.names_mtime = self.mtime()
        self.retention = retention * 3600

        self.db = init_db()

        # Protect SQLite operations from simultaneous collector and
        # HTTP request threads.
        self.db_lock = threading.Lock()

        # Protect the current in-memory peer state.
        self.lock = threading.Lock()

        self.state = {}
        self.prev = {}
        self.error = None

    def mtime(self):
        try:
            if self.names_file:
                return os.path.getmtime(self.names_file)

            return None

        except OSError:
            return None

    def run(self):
        while True:
            try:
                self.collect()
                self.error = None

            except Exception as error:
                self.error = str(error)

                print(
                    "collector error:",
                    error,
                    flush=True,
                )

            time.sleep(self.interval)

    def collect(self):
        current_mtime = self.mtime()

        # Automatically reload peer names when peers.txt changes.
        if current_mtime != self.names_mtime:
            self.names = load_names(self.names_file)
            self.names_mtime = current_mtime

        now = int(time.time())

        snapshot = {}
        rows = []
        daily_rows = []

        for peer in wg_peers():
            public_key = peer["public_key"]

            previous = self.prev.get(
                public_key
            )

            rx_rate = 0.0
            tx_rate = 0.0

            rx_difference = 0
            tx_difference = 0


            if (
                previous
                and now > previous[0]
            ):
                elapsed = (
                    now
                    - previous[0]
                )

                rx_difference = max(
                    0,
                    peer["rx_bytes"]
                    - previous[1],
                )

                tx_difference = max(
                    0,
                    peer["tx_bytes"]
                    - previous[2],
                )

                rx_rate = (
                    rx_difference
                    / elapsed
                )

                tx_rate = (
                    tx_difference
                    / elapsed
                )

            self.prev[public_key] = (
                now,
                peer["rx_bytes"],
                peer["tx_bytes"],
            )

            peer.update(
                name=self.names.get(
                    public_key,
                    public_key[:12] + "...",
                ),
                rx_rate=rx_rate,
                tx_rate=tx_rate,
            )

            if peer["last_handshake"]:
                peer["handshake_age"] = (
                    now - peer["last_handshake"]
                )
            else:
                peer["handshake_age"] = -1

            peer["online"] = (
                0
                <= peer["handshake_age"]
                <= STALE_AFTER
            )

            snapshot[public_key] = peer

            rows.append(
                (
                    now,
                    peer["interface"],
                    public_key,
                    peer["rx_bytes"],
                    peer["tx_bytes"],
                    rx_rate,
                    tx_rate,
                )
            )


            day = time.strftime(
                "%Y-%m-%d",
                time.localtime(now),
            )


            daily_rows.append(
                (
                    day,
                    public_key,
                    rx_difference,
                    tx_difference,
                )
            )

        with self.lock:
            self.state = snapshot

        with self.db_lock:

            # Keep high-resolution samples for the Live tab.

            if rows:
                self.db.executemany(
                    """
                    INSERT INTO samples (
                        ts,
                        iface,
                        pubkey,
                        rx,
                        tx,
                        rx_rate,
                        tx_rate
                    )
                    VALUES (
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?,
                        ?
                    )
                    """,
                    rows,
                )


            # Add each sampling interval to the peer's daily total.
            #
            # Because date + pubkey is the primary key, SQLite either
            # creates the daily row or increments the existing row.

            if daily_rows:
                self.db.executemany(
                    """
                    INSERT INTO daily_usage (
                        date,
                        pubkey,
                        rx,
                        tx
                    )
                    VALUES (
                        ?,
                        ?,
                        ?,
                        ?
                    )

                    ON CONFLICT (
                        date,
                        pubkey
                    )
                    DO UPDATE SET

                        rx =
                            daily_usage.rx
                            + excluded.rx,

                        tx =
                            daily_usage.tx
                            + excluded.tx
                    """,
                    daily_rows,
                )


            # Raw samples are only needed for recent live graphs.

            self.db.execute(
                """
                DELETE FROM samples
                WHERE ts < ?
                """,
                (
                    now - self.retention,
                ),
            )


            self.db.commit()

    def current(self):
        with self.lock:
            return list(
                self.state.values()
            )

    def history(
        self,
        minutes,
        per_peer=False,
    ):
        since = (
            int(time.time())
            - minutes * 60
        )


        with self.db_lock:

            if per_peer:
                query = self.db.execute(
                    """
                    SELECT
                        ts,
                        pubkey,
                        rx_rate,
                        tx_rate

                    FROM samples

                    WHERE ts >= ?

                    ORDER BY
                        ts,
                        pubkey
                    """,
                    (
                        since,
                    ),
                )

                rows = query.fetchall()

            else:
                query = self.db.execute(
                    """
                    SELECT
                        ts,
                        SUM(rx_rate),
                        SUM(tx_rate)

                    FROM samples

                    WHERE ts >= ?

                    GROUP BY ts

                    ORDER BY ts
                    """,
                    (
                        since,
                    ),
                )

                rows = query.fetchall()


        if per_peer:
            return [
                {
                    "ts":
                        row[0],

                    "pubkey":
                        row[1],

                    "rx":
                        row[2]
                        or 0,

                    "tx":
                        row[3]
                        or 0,
                }

                for row in rows
            ]


        return [
            {
                "ts":
                    row[0],

                "rx":
                    row[1]
                    or 0,

                "tx":
                    row[2]
                    or 0,
            }

            for row in rows
        ]

    def daily_stats(
        self,
        days=30,
    ):
        debug_start = time.perf_counter()
        start_date = time.strftime(
            "%Y-%m-%d",
            time.localtime(
                time.time()
                - (
                    days - 1
                )
                * 86400
            ),
        )


        with self.db_lock:
            query = self.db.execute(
                """
                SELECT
                    date,
                    pubkey,
                    rx,
                    tx

                FROM daily_usage

                WHERE date >= ?

                ORDER BY
                    date,
                    pubkey
                """,
                (
                    start_date,
                ),
            )

            rows = query.fetchall()
            debug_sql = time.perf_counter()


        names = {
            peer["public_key"]:
                peer["name"]

            for peer in self.current()
        }


        daily_totals = {}


        for (
            day,
            public_key,
            rx,
            tx,
        ) in rows:

            day_bucket = (
                daily_totals.setdefault(
                    day,
                    {
                        "rx": 0,
                        "tx": 0,
                        "total": 0,
                        "peers": [],
                    },
                )
            )


            total = (
                rx
                + tx
            )


            day_bucket["rx"] += rx
            day_bucket["tx"] += tx
            day_bucket["total"] += total


            day_bucket["peers"].append(
                {
                    "pubkey":
                        public_key,

                    "name":
                        names.get(
                            public_key,
                            public_key[:12]
                            + "...",
                        ),

                    "rx":
                        rx,

                    "tx":
                        tx,

                    "total":
                        total,
                }
            )


        result = []


        for day in sorted(
            daily_totals
        ):

            values = daily_totals[
                day
            ]


            values["peers"].sort(
                key=lambda peer:
                    peer["total"],

                reverse=True,
            )


            result.append(
                {
                    "date":
                        day,

                    "rx":
                        values["rx"],

                    "tx":
                        values["tx"],

                    "total":
                        values["total"],

                    "peers":
                        values["peers"],
                }
            )


        debug_end = time.perf_counter()

        print(
            f"daily_stats: "
            f"SQL={debug_sql - debug_start:.4f}s "
            f"processing={debug_end - debug_sql:.4f}s "
            f"total={debug_end - debug_start:.4f}s",
            flush=True,
        )
        return result[
            -days:
        ]


# ============================================================================
# HTML / CSS / JavaScript
# ============================================================================

PAGE = r"""
<!doctype html>

<html>

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width,initial-scale=1"
    >

    <title>
        WireGuard Monitor
    </title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            font-family:
                Segoe UI,
                system-ui;

            margin: 0;

            background: #0f1420;
            color: #e6e9ef;
        }

        header {
            padding: 16px 24px;

            background: #161d2e;

            border-bottom:
                1px solid #263049;
        }

        h1 {
            font-size: 19px;
            margin: 0;
        }

        .wrap {
            padding: 20px 24px;
        }


        /* ================================================================
           Summary cards
           ================================================================ */

        .cards {
            display: flex;
            gap: 14px;

            flex-wrap: wrap;

            margin-bottom: 20px;
        }

        .card,
        .panel {
            background: #161d2e;

            border:
                1px solid #263049;

            border-radius: 9px;
        }

        .card {
            padding: 14px 18px;
            min-width: 150px;
        }

        .v {
            font-size: 24px;
            font-weight: 600;
        }

        .l {
            font-size: 12px;

            color: #8f9bb3;

            text-transform: uppercase;
        }


        /* ================================================================
           Graphs
           ================================================================ */

        .panel {
            padding: 14px;
            margin-bottom: 20px;
        }

        .title {
            font-size: 14px;
            font-weight: 600;

            margin-bottom: 10px;
        }

        canvas {
            width: 100%;
            height: 250px;

            display: block;
        }

        .legend {
            display: flex;

            gap: 8px 15px;

            flex-wrap: wrap;

            font-size: 12px;

            color: #b9c2d3;

            margin-bottom: 8px;
        }

        .dot {
            display: inline-block;

            width: 10px;
            height: 10px;

            border-radius: 50%;

            margin-right: 7px;
        }


        /* ================================================================
           Tables
           ================================================================ */

        .table {
            overflow-x: auto;
        }

        table {
            width: 100%;

            border-collapse: collapse;

            background: #161d2e;
        }

        th,
        td {
            padding: 10px 14px;

            text-align: left;

            border-bottom:
                1px solid #263049;

            white-space: nowrap;

            font-size: 14px;
        }

        th {
            background: #1c2538;

            color: #8f9bb3;

            font-size: 12px;
        }


        /* ================================================================
           Status
           ================================================================ */

        .up {
            color: #3ddc84;
        }

        .down {
            color: #ff6b6b;
        }

        .err {
            background: #4a1d1d;

            padding: 10px;

            margin-bottom: 14px;
        }


        /* ================================================================
           Tabs
           ================================================================ */

        .tabs {
            display: flex;

            gap: 8px;

            margin-bottom: 18px;
        }

        .tab {
            border:
                1px solid #34415d;

            background: #161d2e;
            color: #b9c2d3;

            padding: 9px 16px;

            border-radius: 7px;

            cursor: pointer;
        }

        .tab.active {
            background: #2878d0;
            color: white;

            border-color: #2878d0;
        }

        .view {
            display: none;
        }

        .view.active {
            display: block;
        }


        /* ================================================================
           Daily view
           ================================================================ */

        .daily-controls {
            display: flex;

            align-items: center;

            gap: 12px;

            margin-bottom: 14px;
        }

        .daily-controls select {
            background: #161d2e;
            color: #e6e9ef;

            border:
                1px solid #34415d;

            padding: 7px;

            border-radius: 6px;
        }

    </style>

</head>


<body>

    <header>
        <h1>
            WireGuard Traffic Monitor
        </h1>
    </header>


    <div class="wrap">

        <div id="err"></div>


        <!-- =============================================================
             Navigation
             ============================================================= -->

        <div class="tabs">

            <button
                class="tab active"
                data-view="liveView"
            >
                Live
            </button>

            <button
                class="tab"
                data-view="dailyView"
            >
                Daily Usage
            </button>

        </div>


        <!-- =============================================================
             LIVE VIEW
             ============================================================= -->

        <section
            id="liveView"
            class="view active"
        >

            <div
                class="cards"
                id="cards"
            ></div>


            <div class="panel">

                <div class="title">
                    Overall VPN Throughput
                </div>

                <canvas id="overall"></canvas>

            </div>


            <div class="panel">

                <div class="title">
                    Traffic by Peer (RX + TX)
                </div>

                <div
                    class="legend"
                    id="legend"
                ></div>

                <canvas id="peers"></canvas>

            </div>


            <div class="table">

                <table>

                    <thead>

                        <tr>
                            <th>Peer</th>
                            <th>Interface</th>
                            <th>Allowed IPs</th>
                            <th>Endpoint</th>
                            <th>Status</th>
                            <th>Last handshake</th>
                            <th>Down</th>
                            <th>Up</th>
                            <th>Total RX</th>
                            <th>Total TX</th>
                        </tr>

                    </thead>


                    <tbody id="rows">
                    </tbody>

                </table>

            </div>

        </section>


        <!-- =============================================================
             DAILY USAGE VIEW
             ============================================================= -->

        <section
            id="dailyView"
            class="view"
        >

            <div class="daily-controls">

                <label>

                    Selected day

                    <select id="daySelect">
                    </select>

                </label>

            </div>


            <div
                class="cards"
                id="dailyCards"
            ></div>


            <div class="panel">

            <div class="title">
                Daily Total Traffic
            </div>

            <canvas id="dailyChart"></canvas>

            </div>

            <div class="panel">

                <div
                    class="title"
                    id="peerDailyTitle"
                >
                    Per-Peer Daily Usage
                </div>

                <canvas id="peerDailyChart"></canvas>

            </div>


        <div class="table">


            <div class="table">

                <table>

                    <thead>

                        <tr>
                            <th>Peer</th>
                            <th>Download (RX)</th>
                            <th>Upload (TX)</th>
                            <th>Total</th>
                            <th>Share</th>
                        </tr>

                    </thead>


                    <tbody id="dailyRows">
                    </tbody>

                </table>

            </div>

        </section>

    </div>


    <script>

        // =================================================================
        // Constants / formatting helpers
        // =================================================================

        const COLORS = [
            "#4da3ff",
            "#3ddc84",
            "#ff9f43",
            "#a55eea",
            "#ff6b6b",
            "#26de81",
            "#fed330",
            "#45aaf2",
            "#fc5c65",
            "#2bcbba",
            "#778ca3",
            "#8854d0",
            "#e84393",
            "#00cec9",
            "#fdcb6e",
            "#74b9ff"
        ];


        function escapeHtml(value) {

            return String(value).replace(
                /[&<>"']/g,
                character => ({
                    "&": "&amp;",
                    "<": "&lt;",
                    ">": "&gt;",
                    '"': "&quot;",
                    "'": "&#39;"
                })[character]
            );
        }


        function formatBytes(bytes) {

            const units = [
                "B",
                "KB",
                "MB",
                "GB",
                "TB"
            ];

            let unitIndex = 0;

            bytes =
                Number(bytes)
                || 0;

            while (
                bytes >= 1024
                && unitIndex < units.length - 1
            ) {
                bytes /= 1024;
                unitIndex++;
            }

            return (
                bytes.toFixed(1)
                + " "
                + units[unitIndex]
            );
        }


        function formatRate(bytes) {
            return (
                formatBytes(bytes)
                + "/s"
            );
        }


        function formatAge(seconds) {

            if (seconds < 0) {
                return "never";
            }

            if (seconds < 60) {
                return seconds + "s ago";
            }

            if (seconds < 3600) {
                return (
                    Math.floor(seconds / 60)
                    + "m ago"
                );
            }

            return (
                Math.floor(seconds / 3600)
                + "h ago"
            );
        }


        // =================================================================
        // Peer colours
        // =================================================================

        function peerColor(key) {

            let hash = 0;

            for (
                let index = 0;
                index < key.length;
                index++
            ) {
                hash =
                    (
                        (hash << 5)
                        - hash
                    )
                    + key.charCodeAt(index);

                hash |= 0;
            }

            return COLORS[
                Math.abs(hash)
                % COLORS.length
            ];
        }


        // =================================================================
        // Canvas helpers
        // =================================================================

        function canvasSetup(id) {

            const canvas =
                document.getElementById(id);

            const ratio =
                devicePixelRatio
                || 1;

            const width =
                Math.max(
                    300,
                    canvas.clientWidth
                );

            const height =
                Math.max(
                    180,
                    canvas.clientHeight
                );

            canvas.width =
                width * ratio;

            canvas.height =
                height * ratio;

            const context =
                canvas.getContext("2d");

            context.setTransform(
                ratio,
                0,
                0,
                ratio,
                0,
                0
            );

            return {
                x: context,
                w: width,
                h: height
            };
        }


        function timeLabel(timestamp) {

            return new Date(
                timestamp * 1000
            ).toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit"
                }
            );
        }


        // =================================================================
        // Chart axis
        // =================================================================

        function drawAxes(
            context,
            width,
            height,
            maxValue,
            firstTimestamp,
            lastTimestamp
        ) {

            const axis = {
                l: 62,
                r: 14,
                t: 16,
                b: 35
            };

            context.font =
                "11px Segoe UI";

            context.strokeStyle =
                "#263049";

            context.fillStyle =
                "#8f9bb3";


            // Y axis

            for (
                let index = 0;
                index <= 4;
                index++
            ) {

                const y =
                    axis.t
                    + index
                    * (
                        height
                        - axis.t
                        - axis.b
                    )
                    / 4;

                const value =
                    maxValue
                    * (4 - index)
                    / 4;

                context.textAlign =
                    "right";

                context.fillText(
                    formatRate(value),
                    axis.l - 7,
                    y + 4
                );

                context.beginPath();

                context.moveTo(
                    axis.l,
                    y
                );

                context.lineTo(
                    width - axis.r,
                    y
                );

                context.stroke();
            }


            // X axis time labels

            for (
                let index = 0;
                index < 6;
                index++
            ) {

                const ratio =
                    index / 5;

                const x =
                    axis.l
                    + ratio
                    * (
                        width
                        - axis.l
                        - axis.r
                    );

                const timestamp =
                    firstTimestamp
                    + (
                        lastTimestamp
                        - firstTimestamp
                    )
                    * ratio;

                context.textAlign =
                    "center";

                context.fillText(
                    timeLabel(timestamp),
                    x,
                    height - 10
                );
            }

            return axis;
        }


        // =================================================================
        // Overall live traffic graph
        // =================================================================

        function drawOverall(data) {

            const {
                x,
                w,
                h
            } = canvasSetup("overall");

            x.clearRect(
                0,
                0,
                w,
                h
            );

            if (!data.length) {
                return;
            }

            const maxValue = Math.max(
                1,
                ...data.flatMap(
                    point => [
                        point.rx,
                        point.tx
                    ]
                )
            );

            const axis = drawAxes(
                x,
                w,
                h,
                maxValue,
                data[0].ts,
                data[data.length - 1].ts
            );

            const pointX = index =>
                axis.l
                + index
                / (
                    data.length - 1
                    || 1
                )
                * (
                    w
                    - axis.l
                    - axis.r
                );

            const pointY = value =>
                h
                - axis.b
                - value
                / maxValue
                * (
                    h
                    - axis.t
                    - axis.b
                );

            [
                [
                    "rx",
                    "#4da3ff"
                ],
                [
                    "tx",
                    "#3ddc84"
                ]
            ].forEach(
                ([key, colour]) => {

                    x.strokeStyle =
                        colour;

                    x.lineWidth = 2;

                    x.beginPath();

                    data.forEach(
                        (
                            point,
                            index
                        ) => {

                            if (index) {
                                x.lineTo(
                                    pointX(index),
                                    pointY(
                                        point[key]
                                    )
                                );
                            }
                            else {
                                x.moveTo(
                                    pointX(index),
                                    pointY(
                                        point[key]
                                    )
                                );
                            }
                        }
                    );

                    x.stroke();
                }
            );
        }


        // =================================================================
        // Live traffic by peer graph
        // =================================================================

        function drawPeerGraph(
            data,
            peers
        ) {

            const {
                x,
                w,
                h
            } = canvasSetup("peers");

            x.clearRect(
                0,
                0,
                w,
                h
            );

            const names =
                Object.fromEntries(
                    peers.map(
                        peer => [
                            peer.public_key,
                            peer.name
                        ]
                    )
                );

            const grouped = {};

            data.forEach(
                point => {

                    if (!grouped[point.pubkey]) {
                        grouped[point.pubkey] = [];
                    }

                    grouped[
                        point.pubkey
                    ].push(
                        {
                            ts: point.ts,
                            value:
                                point.rx
                                + point.tx
                        }
                    );
                }
            );

            const active =
                Object.entries(grouped)
                .filter(
                    ([, points]) =>
                        points.some(
                            point =>
                                point.value > 0
                        )
                );


            document.getElementById(
                "legend"
            ).innerHTML =
                active.length
                    ? active.map(
                        ([key]) => `
                            <span>
                                <i
                                    class="dot"
                                    style="background:${peerColor(key)}"
                                ></i>

                                ${
                                    escapeHtml(
                                        names[key]
                                        || key.slice(0, 12)
                                        + "..."
                                    )
                                }
                            </span>
                        `
                    ).join("")
                    : "No peer traffic in this period";


            if (!active.length) {
                return;
            }

            const allPoints =
                active.flatMap(
                    ([, points]) =>
                        points
                );

            const firstTimestamp =
                Math.min(
                    ...allPoints.map(
                        point => point.ts
                    )
                );

            const lastTimestamp =
                Math.max(
                    ...allPoints.map(
                        point => point.ts
                    )
                );

            const maxValue =
                Math.max(
                    1,
                    ...allPoints.map(
                        point => point.value
                    )
                );

            const axis = drawAxes(
                x,
                w,
                h,
                maxValue,
                firstTimestamp,
                lastTimestamp
            );

            const pointX = timestamp =>
                axis.l
                + (
                    timestamp
                    - firstTimestamp
                )
                / (
                    lastTimestamp
                    - firstTimestamp
                    || 1
                )
                * (
                    w
                    - axis.l
                    - axis.r
                );

            const pointY = value =>
                h
                - axis.b
                - value
                / maxValue
                * (
                    h
                    - axis.t
                    - axis.b
                );

            active.forEach(
                (
                    [
                        key,
                        points
                    ]
                ) => {

                    x.strokeStyle =
                        peerColor(key);

                    x.lineWidth = 2;

                    x.beginPath();

                    points.forEach(
                        (
                            point,
                            index
                        ) => {

                            if (index) {
                                x.lineTo(
                                    pointX(point.ts),
                                    pointY(
                                        point.value
                                    )
                                );
                            }
                            else {
                                x.moveTo(
                  pointX(point.ts),
                                    pointY(
                                        point.value
                                    )
                                );
                            }
                        }
                    );

                    x.stroke();
                }
            );
        }


        // =================================================================
        // Daily traffic graph
        // =================================================================

        let dailyData = [];


        function drawDaily(data) {

            const {
                x,
                w,
                h
            } = canvasSetup(
                "dailyChart"
            );

            x.clearRect(
                0,
                0,
                w,
                h
            );

            if (!data.length) {
                return;
            }

            const maxValue =
                Math.max(
                    1,
                    ...data.map(
                        day => day.total
                    )
                );

            const axis = {
                l: 62,
                r: 14,
                t: 16,
                b: 45
            };

            x.font =
                "11px Segoe UI";


            // Y axis

            for (
                let index = 0;
                index <= 4;
                index++
            ) {

                const y =
                    axis.t
                    + index
                    * (
                        h
                        - axis.t
                        - axis.b
                    )
                    / 4;

                const value =
                    maxValue
                    * (
                        4 - index
                    )
                    / 4;

                x.fillStyle =
                    "#8f9bb3";

                x.textAlign =
                    "right";

                x.fillText(
                    formatBytes(value),
                    axis.l - 7,
                    y + 4
                );

                x.strokeStyle =
                    "#263049";

                x.beginPath();

                x.moveTo(
                    axis.l,
                    y
                );

                x.lineTo(
                    w - axis.r,
                    y
                );

                x.stroke();
            }


            const space =
                (
                    w
                    - axis.l
                    - axis.r
                )
                / data.length;

            const barWidth =
                Math.max(
                    3,
                    space * 0.62
                );


            data.forEach(
                (
                    day,
                    index
                ) => {

                    const barX =
                        axis.l
                        + index * space
                        + (
                            space
                            - barWidth
                        )
                        / 2;

                    const rxHeight =
                        day.rx
                        / maxValue
                        * (
                            h
                            - axis.t
                            - axis.b
                        );

                    const txHeight =
                        day.tx
                        / maxValue
                        * (
                            h
                            - axis.t
                            - axis.b
                        );


                    // RX segment

                    x.fillStyle =
                        "#4da3ff";

                    x.fillRect(
                        barX,
                        h
                            - axis.b
                            - rxHeight,
                        barWidth,
                        rxHeight
                    );


                    // TX segment

                    x.fillStyle =
                        "#3ddc84";

                    x.fillRect(
                        barX,
                        h
                            - axis.b
                            - rxHeight
                            - txHeight,
                        barWidth,
                        txHeight
                    );


                    // X-axis date

                    const date =
                        new Date(
                            day.date
                            + "T00:00:00"
                        );

                    const dateLabel =
                        date.toLocaleDateString(
                            undefined,
                            {
                                month: "short",
                                day: "numeric"
                            }
                        );

                    x.fillStyle =
                        "#8f9bb3";

                    x.font =
                        "11px Segoe UI";

                    x.textAlign =
                        "center";

                    x.fillText(
                        dateLabel,
                        barX
                            + barWidth / 2,
                        h - 12
                    );
                }
            );
        }
        
        // =================================================================
// Per-peer daily usage graph
// =================================================================

        function drawPeerDaily(day) {

            const {
                x,
                w,
                h
            } = canvasSetup(
                "peerDailyChart"
            );


            x.clearRect(
                0,
                0,
                w,
                h
            );


            // Only display peers that transferred data during this day.

            const peers =
                day.peers
                .filter(
                    peer =>
                        peer.total > 0
                )
                .sort(
                    (
                        peerA,
                        peerB
                    ) =>
                        peerB.total
                        - peerA.total
                );


            // Update graph title with selected date.

            const date =
                new Date(
                    day.date
                    + "T00:00:00"
                );

            const dateLabel =
                date.toLocaleDateString(
                    undefined,
                    {
                        month: "short",
                        day: "numeric",
                        year: "numeric"
                    }
                );


            document.getElementById(
                "peerDailyTitle"
            ).textContent =
                "Per-Peer Daily Usage - "
                + dateLabel;


            if (!peers.length) {

                x.fillStyle =
                    "#8f9bb3";

                x.font =
                    "13px Segoe UI";

                x.textAlign =
                    "center";

                x.fillText(
                    "No peer traffic for this day",
                    w / 2,
                    h / 2
                );

                return;
            }


            const maxValue =
                Math.max(
                    1,
                    ...peers.map(
                        peer =>
                            peer.total
                    )
                );


            const axis = {
                l: 70,
                r: 20,
                t: 40,
                b: 65
            };


            const graphHeight =
                h
                - axis.t
                - axis.b;


            // =============================================================
            // Y axis
            // =============================================================

            x.font =
                "11px Segoe UI";


            for (
                let index = 0;
                index <= 4;
                index++
            ) {

                const y =
                    axis.t
                    + index
                    * graphHeight
                    / 4;


                const value =
                    maxValue
                    * (
                        4 - index
                    )
                    / 4;


                x.fillStyle =
                    "#8f9bb3";

                x.textAlign =
                    "right";


                x.fillText(
                    formatBytes(value),
                    axis.l - 8,
                    y + 4
                );


                // Horizontal grid line

                x.strokeStyle =
                    "#263049";

                x.lineWidth = 1;

                x.beginPath();

                x.moveTo(
                    axis.l,
                    y
                );

                x.lineTo(
                    w - axis.r,
                    y
                );

                x.stroke();
            }


            // =============================================================
            // Columns
            // =============================================================

            const availableWidth =
                w
                - axis.l
                - axis.r;


            const columnSpace =
                availableWidth
                / peers.length;


            const barWidth =
                Math.min(
                    90,
                    columnSpace * 0.60
                );


            peers.forEach(
                (
                    peer,
                    index
                ) => {

                    const centerX =
                        axis.l
                        + index
                        * columnSpace
                        + columnSpace / 2;


                    const height =
                        peer.total
                        / maxValue
                        * graphHeight;


                    const barX =
                        centerX
                        - barWidth / 2;


                    const barY =
                        h
                        - axis.b
                        - height;


                    // =====================================================
                    // Peer column
                    // =====================================================

                    x.fillStyle =
                        peerColor(
                            peer.pubkey
                        );


                    x.fillRect(
                        barX,
                        barY,
                        barWidth,
                        height
                    );


                    // =====================================================
                    // Usage value above column
                    // =====================================================

                    x.fillStyle =
                        "#d8deea";

                    x.font =
                        "11px Segoe UI";

                    x.textAlign =
                        "center";


                    x.fillText(
                        formatBytes(
                            peer.total
                        ),
                        centerX,
                        Math.max(
                            15,
                            barY - 8
                        )
                    );


                    // =====================================================
                    // Peer name
                    // =====================================================

                    x.fillStyle =
                        "#8f9bb3";

                    x.font =
                        "11px Segoe UI";

                    x.textAlign =
                        "center";


                    let peerName =
                        peer.name;


                    // Keep very long names from making the chart unreadable.

                    if (
                        peerName.length > 14
                    ) {
                        peerName =
                            peerName.slice(
                                0,
                                12
                            )
                            + "...";
                    }


                    x.fillText(
                        peerName,
                        centerX,
                        h - 25
                    );
                }
            );
        }


        // =================================================================
        // Selected daily usage
        // =================================================================

        function renderDay(date) {

            const day =
                dailyData.find(
                    item =>
                        item.date === date
                );

            if (!day) {
                return;
            }
            
            // Draw per-peer graph for selected day.

            drawPeerDaily(
                day
            );

            // Summary cards

            document.getElementById(
                "dailyCards"
            ).innerHTML = [

                [
                    "Date",
                    day.date
                ],

                [
                    "Total traffic",
                    formatBytes(
                        day.total
                    )
                ],

                [
                    "Download",
                    formatBytes(
                        day.rx
                    )
                ],

                [
                    "Upload",
                    formatBytes(
                        day.tx
                    )
                ],

                [
                    "Active peers",
                    day.peers.filter(
                        peer =>
                            peer.total > 0
                    ).length
                ]

            ].map(
                item => `
                    <div class="card">

                        <div class="l">
                            ${item[0]}
                        </div>

                        <div class="v">
                            ${item[1]}
                        </div>

                    </div>
                `
            ).join("");


            // Daily peer table

            document.getElementById(
                "dailyRows"
            ).innerHTML =
                day.peers.map(
                    peer => `

                        <tr>

                            <td>

                                <i
                                    class="dot"
                                    style="background:${peerColor(peer.pubkey)}"
                                ></i>

                                ${
                                    escapeHtml(
                                        peer.name
                                    )
                                }

                            </td>

                            <td>
                                ${
                                    formatBytes(
                                        peer.rx
                                    )
                                }
                            </td>

                            <td>
                                ${
                                    formatBytes(
                                        peer.tx
                                    )
                                }
                            </td>

                            <td>
                                ${
                                    formatBytes(
                                        peer.total
                                    )
                                }
                            </td>

                            <td>
                                ${
                                    day.total
                                        ? (
                                            (
                                                peer.total
                                                / day.total
                                            )
                                            * 100
                                        ).toFixed(1)
                                        : "0.0"
                                }%
                            </td>

                        </tr>

                    `
                ).join("");
        }


        // =================================================================
        // Daily data loader
        // =================================================================

        async function loadDaily() {

            const response =
                await fetch(
                    "/api/daily?days=30"
                );

            dailyData =
                await response.json();

            const select =
                document.getElementById(
                    "daySelect"
                );

            const selected =
                select.value;


            select.innerHTML =
                [
                    ...dailyData
                ]
                .reverse()
                .map(
                    day => `
                        <option value="${day.date}">
                            ${day.date}
                        </option>
                    `
                )
                .join("");


            if (
                selected
                && dailyData.some(
                    day =>
                        day.date === selected
                )
            ) {
                select.value =
                    selected;
            }


            drawDaily(
                dailyData
            );


            if (dailyData.length) {

                renderDay(
                    select.value
                    || dailyData[
                        dailyData.length - 1
                    ].date
                );
            }
        }


        // =================================================================
        // Tabs
        // =================================================================

        document
            .querySelectorAll(".tab")
            .forEach(
                button => {

                    button.onclick =
                        () => {

                            document
                                .querySelectorAll(
                                    ".tab"
                                )
                                .forEach(
                                    item =>
                                        item.classList.remove(
                                            "active"
                                        )
                                );

                            document
                                .querySelectorAll(
                                    ".view"
                                )
                                .forEach(
                                    item =>
                                        item.classList.remove(
                                            "active"
                                        )
                                );


                            button.classList.add(
                                "active"
                            );

                            document
                                .getElementById(
                                    button.dataset.view
                                )
                                .classList.add(
                                    "active"
                                );


                            if (
                                button.dataset.view
                                === "dailyView"
                            ) {
                                loadDaily();
                            }
                        };
                }
            );


        document.addEventListener(
            "change",
            event => {

                if (
                    event.target.id
                    === "daySelect"
                ) {
                    renderDay(
                        event.target.value
                    );
                }
            }
        );


        // =================================================================
        // Live data
        // =================================================================

        let overallData = [];
        let peerData = [];
        let peerStatus = [];


        async function tick() {

            try {

                const [
                    statusResponse,
                    historyResponse,
                    peerResponse
                ] = await Promise.all(
                    [
                        fetch(
                            "/api/status"
                        ),

                        fetch(
                            "/api/history?minutes=60"
                        ),

                        fetch(
                            "/api/peer-history?minutes=60"
                        )
                    ]
                );


                const status =
                    await statusResponse.json();

                overallData =
                    await historyResponse.json();

                peerData =
                    await peerResponse.json();

                peerStatus =
                    status.peers;


                // Error display

                document.getElementById(
                    "err"
                ).innerHTML =
                    status.error
                        ? `
                            <div class="err">
                                ${
                                    escapeHtml(
                                        status.error
                                    )
                                }
                            </div>
                          `
                        : "";


                const onlinePeers =
                    peerStatus.filter(
                        peer =>
                            peer.online
                    ).length;

                const rxRate =
                    peerStatus.reduce(
                        (
                            total,
                            peer
                        ) =>
                            total
                            + peer.rx_rate,
                        0
                    );

                const txRate =
                    peerStatus.reduce(
                        (
                            total,
                            peer
                        ) =>
                            total
                            + peer.tx_rate,
                        0
                    );

                const totalRx =
                    peerStatus.reduce(
                        (
                            total,
                            peer
                        ) =>
                            total
                            + peer.rx_bytes,
                        0
                    );

                const totalTx =
                    peerStatus.reduce(
                        (
                            total,
                            peer
                        ) =>
                            total
                            + peer.tx_bytes,
                        0
                    );


                // Summary cards

                document.getElementById(
                    "cards"
                ).innerHTML = [

                    [
                        "Peers online",
                        onlinePeers
                        + " / "
                        + peerStatus.length
                    ],

                    [
                        "Download",
                        formatRate(
                            rxRate
                        )
                    ],

                    [
                        "Upload",
                        formatRate(
                            txRate
                        )
                    ],

                    [
                        "Total RX",
                        formatBytes(
                            totalRx
                        )
                    ],

                    [
                        "Total TX",
                        formatBytes(
                            totalTx
                        )
                    ]

                ].map(
                    item => `
                        <div class="card">

                            <div class="l">
                                ${item[0]}
                            </div>

                            <div class="v">
                                ${item[1]}
                            </div>

                        </div>
                    `
                ).join("");


                // Sort:
                // 1. Current traffic
                // 2. Online status
                // 3. Lifetime traffic
                // 4. Name

                const sortedPeers =
                    [
                        ...peerStatus
                    ].sort(
                        (
                            peerA,
                            peerB
                        ) =>

                            (
                                peerB.rx_rate
                                + peerB.tx_rate
                            )
                            -
                            (
                                peerA.rx_rate
                                + peerA.tx_rate
                            )

                            ||

                            (
                                Number(
                                    peerB.online
                                )
                                -
                                Number(
                                    peerA.online
                                )
                            )

                            ||

                            (
                                peerB.rx_bytes
                                + peerB.tx_bytes
                            )
                            -
                            (
                                peerA.rx_bytes
                                + peerA.tx_bytes
                            )

                            ||

                            peerA.name.localeCompare(
                                peerB.name
                            )
                    );


                // Live peer table

                document.getElementById(
                    "rows"
                ).innerHTML =
                    sortedPeers.map(
                        peer => `

                            <tr>

                                <td>

                                    <i
                                        class="dot"
                                        style="background:${peerColor(peer.public_key)}"
                                    ></i>

                                    ${
                                        escapeHtml(
                                            peer.name
                                        )
                                    }

                                </td>

                                <td>
                                    ${
                                        escapeHtml(
                                            peer.interface
                                        )
                                    }
                                </td>

                                <td>
                                    ${
                                        escapeHtml(
                                            peer.allowed_ips
                                        )
                                    }
                                </td>

                                <td>
                                    ${
                                        escapeHtml(
                                            peer.endpoint
                                            || "-"
                                        )
                                    }
                                </td>

                                <td
                                    class="${
                                        peer.online
                                            ? "up"
                                            : "down"
                                    }"
                                >
                                    ${
                                        peer.online
                                            ? "online"
                                            : "offline"
                                    }
                                </td>

                                <td>
                                    ${
                                        formatAge(
                                            peer.handshake_age
                                        )
                                    }
                                </td>

                                <td>
                                    ${
                                        formatRate(
                                            peer.rx_rate
                                        )
                                    }
                                </td>

                                <td>
                                    ${
                                        formatRate(
                                            peer.tx_rate
                                        )
                                    }
                                </td>

                                <td>
                                    ${
                                        formatBytes(
                                            peer.rx_bytes
                                        )
                                    }
                                </td>

                                <td>
                                    ${
                                        formatBytes(
                                            peer.tx_bytes
                                        )
                                    }
                                </td>

                            </tr>

                        `
                    ).join("");


                drawOverall(
                    overallData
                );

                drawPeerGraph(
                    peerData,
                    peerStatus
                );
            }

            catch (error) {

                document.getElementById(
                    "err"
                ).innerHTML = `
                    <div class="err">
                        ${
                            escapeHtml(
                                error
                            )
                        }
                    </div>
                `;
            }
        }


        // =================================================================
        // Resize handling
        // =================================================================

        let resizeTimer;

        addEventListener(
            "resize",
            () => {

                clearTimeout(
                    resizeTimer
                );

                resizeTimer =
                    setTimeout(
                        () => {

                            drawOverall(
                                overallData
                            );

                            drawPeerGraph(
                                peerData,
                                peerStatus
                            );

                            if (
                                dailyData.length
                            ) {

                                drawDaily(
                                    dailyData
                                );


                                const selectedDate =
                                    document.getElementById(
                                        "daySelect"
                                    ).value;


                                const selectedDay =
                                    dailyData.find(
                                        day =>
                                            day.date
                                            === selectedDate
                                    );


                                if (selectedDay) {

                                    drawPeerDaily(
                                        selectedDay
                                    );
                                }
                            }
                        },
                        150
                    );
            }
        );


        // =================================================================
        // Start
        // =================================================================

        tick();

        setInterval(
            tick,
            5000
        );

    </script>

</body>

</html>
"""


# ============================================================================
# HTTP Handler
# ============================================================================

class Handler(BaseHTTPRequestHandler):
    collector = None

    def send_content(
        self,
        status_code,
        body,
        content_type,
    ):
        data = body.encode()

        self.send_response(
            status_code
        )

        self.send_header(
            "Content-Type",
            content_type,
        )

        self.send_header(
            "Content-Length",
            str(len(data)),
        )

        self.send_header(
            "Cache-Control",
            "no-store",
        )

        self.end_headers()

        self.wfile.write(
            data
        )

    def minutes(self):
        try:
            query = parse_qs(
                urlparse(
                    self.path
                ).query
            )

            return max(
                1,
                min(
                    int(
                        query.get(
                            "minutes",
                            ["60"],
                        )[0]
                    ),
                    2880,
                ),
            )

        except ValueError:
            return 60

    def do_GET(self):
        path = urlparse(
            self.path
        ).path

        collector = self.collector

        if path == "/":

            self.send_content(
                200,
                PAGE,
                "text/html; charset=utf-8",
            )

        elif path == "/api/status":

            self.send_content(
                200,
                json.dumps(
                    {
                        "peers":
                            collector.current(),

                        "error":
                            collector.error,
                    }
                ),
                "application/json",
            )

        elif path == "/api/history":

            self.send_content(
                200,
                json.dumps(
                    collector.history(
                        self.minutes()
                    )
                ),
                "application/json",
            )

        elif path == "/api/peer-history":

            self.send_content(
                200,
                json.dumps(
                    collector.history(
                        self.minutes(),
                        True,
                    )
                ),
                "application/json",
            )

        elif path == "/api/daily":

            try:
                query = parse_qs(
                    urlparse(
                        self.path
                    ).query
                )

                days = max(
                    1,
                    min(
                        int(
                            query.get(
                                "days",
                                ["30"],
                            )[0]
                        ),
                        365,
                    ),
                )

            except ValueError:
                days = 30

            self.send_content(
                200,
                json.dumps(
                    collector.daily_stats(
                        days
                    )
                ),
                "application/json",
            )

        else:

            self.send_content(
                404,
                "not found",
                "text/plain",
            )

    def log_message(
        self,
        *args,
    ):
        pass


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "WireGuard traffic monitoring dashboard"
        )
    )

    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Address on which the dashboard listens",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Dashboard TCP port",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="WireGuard polling interval in seconds",
    )

    parser.add_argument(
        "--names",
        help="Path to the peer names file",
    )

    parser.add_argument(
        "--retention-hours",
        type=int,
        default=48,
        help="History retention period in hours",
    )

    args = parser.parse_args()


    collector = Collector(
        args.interval,
        args.names,
        args.retention_hours,
    )

    collector.start()


    Handler.collector = collector


    print(
        (
            "wg-dashboard listening on "
            f"http://{args.bind}:{args.port}"
        ),
        flush=True,
    )


    server = ThreadingHTTPServer(
        (
            args.bind,
            args.port,
        ),
        Handler,
    )

    server.serve_forever()


if __name__ == "__main__":
    main()