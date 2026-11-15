#!/usr/bin/env python3

import csv
import io
import ssl
import json
import re
import threading
import time
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from iox_logger_tls import ensure_certificate
from iox_logger_auth import (
    read_credentials, check_password, create_initial_password,
    change_password, complete_recovery, recovery_path,
    save_program_credentials, read_program_credentials,
)
from iox_logger_sessions import (
    create_session, validate_session, destroy_session,
    destroy_all_sessions, login_allowed, record_login_failure,
    clear_login_failures,
)
from iox_logger_program_history import ProgramHistory


import udi_interface
import markdown2

LOGGER = udi_interface.LOGGER
polyglot = udi_interface.Interface([])


DATA_DIR = Path(__file__).resolve().parent / "data"
CONFIG_FILE = DATA_DIR / "loggers.json"
AUTH_BASE = Path(__file__).resolve().parent
AUTH_LOCK = threading.RLock()

# CSV storage limits
CSV_ROTATE_BYTES = 2 * 1024 * 1024       # 2 MB per file
LOGGER_MAX_BYTES = 10 * 1024 * 1024      # 10 MB total per logger
PLUGIN_MAX_BYTES = 1024 * 1024 * 1024    # 1 GB total CSV storage


class LoggerHTTPSServer(ThreadingHTTPServer):
    """Perform TLS handshakes in worker threads, not the accept loop."""

    daemon_threads = True

    def __init__(self, address, handler, ssl_context):
        super().__init__(address, handler)
        self.ssl_context = ssl_context

    def process_request_thread(self, request, client_address):
        # Detect HTTP or HTTPS inside the worker thread.
        sock = request
        try:
            sock.settimeout(5)
            first = sock.recv(1, __import__("socket").MSG_PEEK)
            if first == bytes([0x16]):
                sock = self.ssl_context.wrap_socket(
                    sock, server_side=True
                )
                handler = self.RequestHandlerClass
            elif first:
                handler = LoggerHTTPRedirectHandler
            else:
                return

            handler(sock, client_address, self)
        except (OSError, ssl.SSLError):
            return
        finally:
            sock.close()
            if sock is not request:
                request.close()


class LoggerHTTPRedirectHandler(BaseHTTPRequestHandler):
    """Redirect plaintext HTTP without processing credentials."""

    def redirect_https(self):
        host = self.headers.get("Host", "")
        if not re.fullmatch(r"[A-Za-z0-9.\\-]+(?::[0-9]{1,5})?", host):
            host = self.connection.getsockname()[0]
        if ":" not in host:
            host += f":{self.server.server_address[1]}"

        path = self.path
        if not path.startswith("/") or path.startswith("//"):
            path = "/"

        self.send_response(308)
        self.send_header("Location", f"https://{host}{path}")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    do_GET = redirect_https
    do_HEAD = redirect_https
    do_POST = redirect_https
    do_PUT = redirect_https
    do_PATCH = redirect_https
    do_DELETE = redirect_https
    do_OPTIONS = redirect_https


class LoggerWebHandler(BaseHTTPRequestHandler):
    controller = None

    SESSION_COOKIE = "iox_logger_session"

    def session_token(self):
        from http.cookies import SimpleCookie
        try:
            cookies = SimpleCookie()
            cookies.load(self.headers.get("Cookie", ""))
            item = cookies.get(self.SESSION_COOKIE)
            return item.value if item else None
        except Exception:
            return None

    def set_session_cookie(self, token):
        self.send_header("Set-Cookie", f"{self.SESSION_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict")

    def clear_session_cookie(self):
        self.send_header("Set-Cookie", f"{self.SESSION_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")

    def valid_request_origin(self):
        from urllib.parse import urlsplit
        origin = self.headers.get("Origin")
        if not origin:
            return False
        parsed = urlsplit(origin)
        return parsed.scheme == "https" and parsed.netloc == self.headers.get("Host", "")

    def send_json(self, value, status=200):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def serve_auth_page(self, filename):
        path = AUTH_BASE / filename
        if not path.is_file():
            self.send_error(404, "Authentication page missing")
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def require_auth(self):
        if validate_session(self.session_token()):
            return True
        self.send_response(401)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def read_json_request(self):
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise ValueError("JSON content type required")
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 8192:
            raise ValueError("Invalid request size")
        data = json.loads(self.rfile.read(size))
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        return data

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/status":
            self.send_json({"configured": read_credentials(AUTH_BASE) is not None})
            return
        if parsed.path == "/auth":
            self.serve_auth_page("iox_logger_password.html")
            return
        if parsed.path == "/login":
            if read_credentials(AUTH_BASE) is None:
                self.redirect("/auth")
            else:
                self.serve_auth_page("iox_logger_login.html")
            return
        if not validate_session(self.session_token()):
            if parsed.path in ("/", "/editor"):
                self.redirect("/login" if read_credentials(AUTH_BASE) is not None else "/auth")
            else:
                self.require_auth()
            return
        if parsed.path == "/program-history":
            try:
                q = parse_qs(parsed.query)
                self.send_json(self.controller.program_history.query(
                    search=q.get("search", [""])[0],
                    sort=q.get("sort", ["newest"])[0],
                    page=int(q.get("page", ["1"])[0]),
                ))
            except (ValueError, TypeError):
                self.send_error(400, "Invalid query")
            return
        if parsed.path == "/program-settings":
            self.send_json(self.controller.program_history.settings())
            return
        if parsed.path == "/program-download":
            self.send_program_download(parsed)
            return
        if parsed.path == "/editor":
            self.redirect("/")
            return

        if parsed.path == "/values":
            self.send_values(parsed)
            return

        if parsed.path == "/download":
            self.send_download(parsed)
            return

        if parsed.path == "/graph":
            self.send_graph(parsed)
            return

        if parsed.path == "/loggers":
            self.send_loggers()
            return

        if parsed.path != "/":
            self.send_error(404)
            return

        catalog = self.controller.web_catalog if self.controller else {}

        source_options = []
        nodes_js = {}

        def source_sort_key(source):
            if source == "native":
                return (0, 0)
            return (1, int(source))

        for slot in sorted(catalog, key=source_sort_key):
            info = catalog[slot]
            source_name = info["source_name"]
            source_options.append(
                f'<option value="{slot}">{source_name}</option>'
            )
            nodes_js[slot] = [
                {"name": n["name"], "address": n["address"]}
                for n in info["nodes"]
            ]

        import json
        source_html = "".join(source_options)
        nodes_json = json.dumps(nodes_js)
        if self.controller:
            with self.controller.logger_lock:
                initial_loggers = [
                    entry.copy()
                    for entry in self.controller.configured_loggers
                ]
        else:
            initial_loggers = []

        loggers_json = json.dumps(initial_loggers)

        html = f"""<!doctype html>
<html>
<head>
  <title>IoX Logger</title>
  <style>
    * {{
      box-sizing: border-box;
    }}

    body {{
      margin: 0;
      padding: 32px;
      background: #f1f5f9;
      color: #1e293b;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                   Roboto, Arial, sans-serif;
      font-size: 14px;
    }}

    body > * {{
      max-width: 1150px;
      margin-left: auto;
      margin-right: auto;
    }}

    h1 {{
      margin-top: 0;
      margin-bottom: 24px;
      padding: 20px 24px;
      background: linear-gradient(135deg, #17365d, #245b91);
      color: white;
      border-radius: 10px;
      font-size: 26px;
      font-weight: 600;
      letter-spacing: .2px;
      box-shadow: 0 3px 10px rgba(0,0,0,.12);
    }}

    h2 {{
      margin-top: 32px;
      margin-bottom: 12px;
      color: #17365d;
      font-size: 19px;
      font-weight: 600;
    }}

    body > p {{
      margin-top: 0;
      margin-bottom: 0;
      padding: 8px 20px;
      background: white;
      border-left: 1px solid #dbe3ec;
      border-right: 1px solid #dbe3ec;
    }}

    body > p:nth-of-type(1) {{
      padding-top: 20px;
      border-top: 1px solid #dbe3ec;
      border-radius: 10px 10px 0 0;
    }}

    body > p:nth-of-type(5) {{
      padding-bottom: 20px;
      border-bottom: 1px solid #dbe3ec;
      border-radius: 0 0 10px 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,.06);
    }}

    label {{
      display: inline-block;
      width: 85px;
      font-weight: 600;
      color: #475569;
    }}

    select {{
      min-width: 300px;
      padding: 8px 34px 8px 10px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      background: white;
      color: #1e293b;
      font-size: 14px;
    }}

    select:focus {{
      outline: none;
      border-color: #2563a6;
      box-shadow: 0 0 0 3px rgba(37,99,166,.12);
    }}

    button {{
      padding: 7px 12px;
      border: 1px solid #b8c5d3;
      border-radius: 6px;
      background: #ffffff;
      color: #24415f;
      font-weight: 500;
      cursor: pointer;
      transition: background .15s, border-color .15s,
                  transform .05s;
    }}

    button:hover {{
      background: #eaf2f9;
      border-color: #7896b5;
    }}

    button:active {{
      transform: translateY(1px);
    }}

    #addLogger {{
      margin-left: 85px;
      padding: 9px 18px;
      border-color: #1e5d94;
      background: #2563a6;
      color: white;
      font-weight: 600;
    }}

    #addLogger:hover {{
      background: #1d528b;
    }}

    #message {{
      min-height: 18px;
      margin-top: 10px;
      color: #2563a6;
      font-weight: 500;
    }}

    table {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      overflow: hidden;
      background: white;
      border: 1px solid #dbe3ec;
      border-radius: 10px;
      box-shadow: 0 2px 8px rgba(0,0,0,.06);
    }}

    th {{
      padding: 11px 12px;
      background: #17365d;
      color: white;
      text-align: left;
      font-size: 13px;
      font-weight: 600;
      white-space: nowrap;
    }}

    td {{
      padding: 11px 12px;
      border-bottom: 1px solid #e7edf3;
      vertical-align: middle;
    }}

    tr:last-child td {{
      border-bottom: none;
    }}

    tr:nth-child(even) td {{
      background: #f8fafc;
    }}

    tr:hover td {{
      background: #edf5fb;
    }}

    td a {{
      color: #1769aa;
      font-weight: 600;
      text-decoration: none;
    }}

    td a:hover {{
      text-decoration: underline;
    }}

    td:last-child {{
      white-space: nowrap;
    }}

    td:last-child button {{
      margin-top: 2px;
      margin-bottom: 2px;
    }}

    dialog {{
      min-width: 430px;
      padding: 24px;
      border: 0;
      border-radius: 10px;
      background: white;
      color: #1e293b;
      box-shadow: 0 18px 50px rgba(0,0,0,.28);
    }}

    dialog::backdrop {{
      background: rgba(15,23,42,.45);
    }}

    dialog p {{
      margin-top: 0;
      margin-bottom: 18px;
      color: #17365d;
      font-size: 16px;
      font-weight: 600;
    }}

    dialog select {{
      min-width: 240px;
    }}

    dialog button {{
      margin-left: 8px;
    }}

    @media (max-width: 800px) {{
      body {{
        padding: 10px;
      }}

      h1 {{
        padding: 16px;
        font-size: 22px;
        border-radius: 8px;
      }}

      body > p {{
        padding-left: 15px;
        padding-right: 15px;
      }}

      label {{
        display: block;
        width: auto;
        margin-bottom: 5px;
      }}

      select {{
        width: 100%;
        min-width: 0;
      }}

      #addLogger {{
        width: 100%;
        margin-left: 0;
      }}

      #activeLoggers table,
      #activeLoggers tbody,
      #activeLoggers tr,
      #activeLoggers td {{
        display: block;
        width: 100%;
      }}

      #activeLoggers table {{
        border: 0;
        background: transparent;
        box-shadow: none;
      }}

      #activeLoggers tr:first-child {{
        display: none;
      }}

      #activeLoggers tr {{
        margin-bottom: 14px;
        overflow: hidden;
        border: 1px solid #dbe3ec;
        border-radius: 10px;
        background: white;
        box-shadow: 0 2px 8px rgba(0,0,0,.06);
      }}

      #activeLoggers td {{
        display: grid;
        grid-template-columns: 90px minmax(0, 1fr);
        column-gap: 10px;
        align-items: center;
        min-height: 42px;
        padding: 9px 12px;
        border-bottom: 1px solid #e7edf3;
        background: white;
        font-size: 13px;
        overflow-wrap: anywhere;
      }}

      #activeLoggers tr:nth-child(even) td,
      #activeLoggers tr:hover td {{
        background: white;
      }}

      #activeLoggers td::before {{
        position: static;
        width: auto;
        color: #64748b;
        font-size: 12px;
        font-weight: 600;
      }}

      #activeLoggers td:nth-child(1)::before {{
        content: "Node";
      }}

      #activeLoggers td:nth-child(2)::before {{
        content: "Value";
      }}

      #activeLoggers td:nth-child(3)::before {{
        content: "Latest";
      }}

      #activeLoggers td:nth-child(4)::before {{
        content: "Interval";
      }}

      #activeLoggers td:nth-child(5)::before {{
        content: "Last Sample";
      }}

      #activeLoggers td:nth-child(6)::before {{
        content: "Storage";
      }}

      #activeLoggers td:nth-child(7) {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 7px;
        padding: 10px;
        border-bottom: 0;
      }}

      #activeLoggers td:nth-child(7)::before {{
        content: none;
      }}

      #activeLoggers td:last-child {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 7px;
      }}

      #activeLoggers td:last-child button,
      #activeLoggers td:last-child a {{
        width: 100%;
        margin: 0 !important;
        text-align: center;
      }}

      #activeLoggers td:last-child a {{
        padding: 7px 8px;
        border: 1px solid #b8c5d3;
        border-radius: 6px;
        background: white;
        text-decoration: none;
      }}

      dialog {{
        width: calc(100% - 30px);
        min-width: 0;
        padding: 20px;
      }}

      dialog select {{
        width: 100%;
        min-width: 0;
        margin-bottom: 15px;
      }}
    }}
  </style>
</head>
<body>
  <h1>IoX Logger <span style="float:right;font-size:13px"><a href="/auth" style="color:white">Password</a> &nbsp; <button type="button" id="logoutButton">Log out</button></span></h1>

  <p>
    <label>Source:</label>
    <select id="source">
      {source_html}
    </select>
  </p>

  <p>
    <label>Node:</label>
    <select id="node"></select>
  </p>

  <p>
    <label>Value:</label>
    <select id="value"></select>
  </p>

  <p>
    <label>Interval:</label>
    <select id="interval">
      <option value="0">On Change (5 sec polling)</option>
      <option value="60">1 minute</option>
      <option value="300" selected>5 minutes</option>
      <option value="600">10 minutes</option>
      <option value="900">15 minutes</option>
      <option value="1800">30 minutes</option>
      <option value="3600">60 minutes</option>
    </select>
  </p>

  <p>
    <button type="button" id="addLogger">Add Logger</button>
  </p>

  <p id="message"></p>

  <h2>Active Loggers</h2>
  <div id="activeLoggers"></div>

  <hr style="margin:32px 0">

  <h2>Program Execution History</h2>
  <section style="background:white;padding:16px 20px;border-radius:8px;border:1px solid #dbe3ec">
    <div style="display:flex;flex-wrap:wrap;gap:14px;align-items:center">
      <label style="width:auto"><input type="checkbox" id="programEnabled"> Enable program logging</label>
      <label style="width:auto">Retain for <select id="programRetention" style="min-width:110px">
        <option value="7">7 days</option><option value="14">14 days</option>
        <option value="30">30 days</option><option value="60">60 days</option>
        <option value="90">90 days</option><option value="180">180 days</option>
        <option value="365">365 days</option>
      </select></label>
      <button type="button" id="programSaveSettings">Save Settings</button>
      <span id="programSettingsMessage" role="status"></span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:10px;margin:16px 0">
      <input id="programSearch" placeholder="Search name, ID, branch, date" style="flex:1;min-width:220px;padding:8px">
      <select id="programSort" style="min-width:160px"><option value="newest">Newest first</option><option value="oldest">Oldest first</option><option value="name">Program name</option></select>
      <button type="button" id="programDownload">Download CSV</button>
    </div>
    <div style="overflow-x:auto"><table style="width:100%"><thead><tr><th>Time</th><th>Program</th><th>ID</th><th>Branch</th></tr></thead><tbody id="programHistoryRows"></tbody></table></div>
    <div style="display:flex;gap:12px;align-items:center;margin-top:12px">
      <button type="button" id="programPrev">Previous</button><span id="programPageInfo"></span><button type="button" id="programNext">Next</button>
    </div>
  </section>

  <h2>Program Monitor</h2>
  <p>Local IoX credentials for monitoring program executions. Not Portal Credentials.</p>

  <form id="programConfigForm">
    <p>
      <label for="programUsername">IoX Username:</label>
      <input id="programUsername" type="text"
             value="admin" autocomplete="username" required>
    </p>

    <p>
      <label for="programPassword">IoX Password:</label>
      <input id="programPassword" type="password"
             autocomplete="new-password" required>
    </p>

    <p>
      <button type="submit">Save Credentials</button>
    </p>
  </form>

  <p id="programConfigMessage" role="status"></p>

<script>
const nodes = {nodes_json};
let activeLoggers = {loggers_json};

function renderLoggers() {{
    const area = document.getElementById("activeLoggers");

    if (!activeLoggers.length) {{
        area.textContent = "None";
        return;
    }}

    area.innerHTML = "";

    const table = document.createElement("table");
    table.style.borderCollapse = "collapse";

    const header = document.createElement("tr");

    for (const title of [
        "Node",
        "Value",
        "Latest",
        "Interval",
        "Last Sample",
        "Storage",
        "Actions"
    ]) {{
        const th = document.createElement("th");
        th.textContent = title;
        th.style.textAlign = "left";
        th.style.padding = "4px 16px 4px 4px";
        header.appendChild(th);
    }}

    table.appendChild(header);

    activeLoggers.forEach((logger, index) => {{
        const row = document.createElement("tr");

        let lastSample = "--";
        if (logger.last_sample) {{
            lastSample = new Date(
                logger.last_sample
            ).toLocaleTimeString();
        }}

        const intervalMinutes = logger.interval / 60;

        function formatBytes(bytes) {{
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024)
                return (bytes / 1024).toFixed(1) + " KB";
            return (bytes / (1024 * 1024)).toFixed(1) + " MB";
        }}

        const storage =
            formatBytes(logger.storage_bytes ?? 0) + " / 10 MB";

        for (const value of [
            logger.node_name,
            logger.value_name,
            logger.latest_value ?? "--",
            logger.interval === 0
                ? "On Change (5 sec polling)"
                : intervalMinutes + " min",
            lastSample,
            storage
        ]) {{
            const td = document.createElement("td");
            td.textContent = value;
            td.style.padding = "4px 16px 4px 4px";
            row.appendChild(td);
        }}

        const actions = document.createElement("td");
        actions.style.padding = "4px";

        const download = document.createElement("a");
        download.textContent = "Download";
        download.href =
            "/download?node=" +
            encodeURIComponent(logger.node_address) +
            "&driver=" +
            encodeURIComponent(logger.driver);
        download.style.marginRight = "12px";

        const editInterval = document.createElement("button");
        editInterval.type = "button";
        editInterval.textContent = "Edit Interval";
        editInterval.style.marginRight = "8px";
        editInterval.onclick = () => editLoggerInterval(index);

        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.textContent =
            logger.enabled === false ? "Enable" : "Disable";
        toggle.style.marginRight = "8px";
        toggle.onclick = () => toggleLogger(index);

        const del = document.createElement("button");
        del.type = "button";
        del.textContent = "Delete";
        del.onclick = () => deleteLogger(index);

        const graph = document.createElement("a");
        graph.href =
            "/graph?node=" +
            encodeURIComponent(logger.node_address) +
            "&driver=" +
            encodeURIComponent(logger.driver);
        graph.textContent = "Graph";
        graph.target = "_blank";
        graph.style.marginRight = "8px";

        actions.appendChild(download);
        actions.appendChild(graph);
        actions.appendChild(editInterval);
        actions.appendChild(toggle);
        actions.appendChild(del);
        row.appendChild(actions);

        table.appendChild(row);
    }});

    area.appendChild(table);
}}

async function editLoggerInterval(index) {{
    const logger = activeLoggers[index];
    const message = document.getElementById("message");

    const labels = {{
        0: "On Change (5 sec polling)",
        60: "1 minute",
        300: "5 minutes",
        600: "10 minutes",
        900: "15 minutes",
        1800: "30 minutes",
        3600: "60 minutes"
    }};

    const select = document.createElement("select");

    for (const interval of [
        0, 60, 300, 600, 900, 1800, 3600
    ]) {{
        const option = document.createElement("option");
        option.value = interval;
        option.textContent = labels[interval];

        if (Number(logger.interval) === interval) {{
            option.selected = true;
        }}

        select.appendChild(option);
    }}

    const dialog = document.createElement("dialog");

    const title = document.createElement("p");
    title.textContent =
        logger.node_name + " - " + logger.value_name;

    const save = document.createElement("button");
    save.type = "button";
    save.textContent = "Save";
    save.style.marginLeft = "8px";

    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.textContent = "Cancel";
    cancel.style.marginLeft = "8px";

    dialog.appendChild(title);
    dialog.appendChild(select);
    dialog.appendChild(save);
    dialog.appendChild(cancel);

    document.body.appendChild(dialog);

    cancel.onclick = () => {{
        dialog.close();
        dialog.remove();
    }};

    save.onclick = async () => {{
        const interval = Number(select.value);

        const response = await fetch("/interval", {{
            method: "POST",
            headers: {{"Content-Type": "application/json"}},
            body: JSON.stringify({{
                node_address: logger.node_address,
                driver: logger.driver,
                interval: interval
            }})
        }});

        const result = await response.json();

        if (!result.ok) {{
            message.textContent = "Error: " + result.error;
            return;
        }}

        dialog.close();
        dialog.remove();

        await loadLoggers();
        message.textContent = "Logger interval updated.";
    }};

    dialog.showModal();
}}

async function toggleLogger(index) {{
    const logger = activeLoggers[index];
    const message = document.getElementById("message");
    const enabled = logger.enabled === false;

    const response = await fetch("/enable", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify({{
            node_address: logger.node_address,
            driver: logger.driver,
            enabled: enabled
        }})
    }});

    const result = await response.json();

    if (!result.ok) {{
        message.textContent = "Error: " + result.error;
        return;
    }}

    activeLoggers[index] = result.logger;
    renderLoggers();

    message.textContent =
        enabled ? "Logger enabled." : "Logger disabled.";
}}

async function deleteLogger(index) {{
    const logger = activeLoggers[index];
    const message = document.getElementById("message");

    if (!confirm(
        "Delete logger " +
        logger.node_name + " - " +
        logger.value_name + "?\\n\\n" +
        "All historical CSV data for this logger will also be deleted. " +
        "This cannot be undone."
    )) {{
        return;
    }}

    const response = await fetch("/delete", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify({{
            node_address: logger.node_address,
            driver: logger.driver
        }})
    }});

    const result = await response.json();

    if (!result.ok) {{
        message.textContent = "Error: " + result.error;
        return;
    }}

    activeLoggers.splice(index, 1);
    renderLoggers();
    message.textContent =
        "Logger and associated CSV data deleted.";
}}

async function addLogger() {{
    const sourceSelect = document.getElementById("source");
    const nodeSelect = document.getElementById("node");
    const valueSelect = document.getElementById("value");
    const intervalSelect = document.getElementById("interval");
    const message = document.getElementById("message");

    const payload = {{
        source_name:
            sourceSelect.options[sourceSelect.selectedIndex].text,
        node_address: nodeSelect.value,
        node_name:
            nodeSelect.options[nodeSelect.selectedIndex].text,
        driver: valueSelect.value,
        value_name:
            valueSelect.options[valueSelect.selectedIndex].text,
        interval: Number(intervalSelect.value)
    }};

    const response = await fetch("/add", {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify(payload)
    }});

    const result = await response.json();

    if (!result.ok) {{
        message.textContent = "Error: " + result.error;
        return;
    }}

    activeLoggers.push(result.logger);
    renderLoggers();
    message.textContent = "Logger added.";
}}

function loadNodes() {{
    const source = document.getElementById("source").value;
    const nodeSelect = document.getElementById("node");
    nodeSelect.innerHTML = "";

    for (const node of (nodes[source] || [])) {{
        const option = document.createElement("option");
        option.value = node.address;
        option.textContent = node.name;
        nodeSelect.appendChild(option);
    }}
}}

async function loadValues() {{
    const address = document.getElementById("node").value;
    const valueSelect = document.getElementById("value");
    valueSelect.innerHTML = "";

    if (!address) return;

    const response = await fetch(
        "/values?node=" + encodeURIComponent(address)
    );

    const values = await response.json();

    for (const item of values) {{
        const option = document.createElement("option");
        option.value = item.driver;
        option.textContent = item.label;
        valueSelect.appendChild(option);
    }}
}}

document.getElementById("source").addEventListener("change", () => {{
    loadNodes();
    loadValues();
}});

document.getElementById("node").addEventListener("change", loadValues);

document.getElementById("addLogger").addEventListener(
    "click", addLogger
);

async function refreshLoggers() {{
    try {{
        const response = await fetch("/loggers");

        if (!response.ok) return;

        activeLoggers = await response.json();
        renderLoggers();

    }} catch (error) {{
        console.error("Logger refresh failed:", error);
    }}
}}

document.getElementById("programConfigForm").addEventListener(
    "submit", async (event) => {{
        event.preventDefault();

        const message = document.getElementById(
            "programConfigMessage"
        );
        message.textContent = "Saving...";

        try {{
            const response = await fetch("/program-config", {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify({{
                    username: document.getElementById(
                        "programUsername"
                    ).value,
                    password: document.getElementById(
                        "programPassword"
                    ).value
                }})
            }});

            const result = await response.json();

            if (!response.ok || !result.ok) {{
                throw new Error(result.error || "Save failed");
            }}

            document.getElementById("programPassword").value = "";
            message.textContent =
                "Credentials saved. Restart IoX Logger to apply.";

        }} catch (error) {{
            message.textContent = "Error: " + error.message;
        }}
    }}
);

let programPage = 1;
let programTotalPages = 1;
const programSearch = document.getElementById("programSearch");
const programSort = document.getElementById("programSort");
async function refreshProgramHistory() {{
    const params = new URLSearchParams({{
        page: String(programPage), search: programSearch.value, sort: programSort.value
    }});
    try {{
        const response = await fetch("/program-history?" + params, {{cache:"no-store"}});
        if (!response.ok) throw new Error("History request failed");
        const result = await response.json();
        programTotalPages = Math.max(1, Math.ceil(result.total / result.page_size));
        const tbody = document.getElementById("programHistoryRows");
        tbody.replaceChildren();
        for (const event of result.events) {{
            const tr = document.createElement("tr");
            for (const value of [event.timestamp, event.program_name, event.program_id, event.branch]) {{
                const td = document.createElement("td");
                td.textContent = value;
                td.style.padding = "8px";
                tr.appendChild(td);
            }}
            tbody.appendChild(tr);
        }}
        document.getElementById("programPageInfo").textContent =
            `Page ${{programPage}} of ${{programTotalPages}} (${{result.total}} events)`;
        document.getElementById("programPrev").disabled = programPage <= 1;
        document.getElementById("programNext").disabled = programPage >= programTotalPages;
    }} catch (error) {{
        document.getElementById("programPageInfo").textContent = error.message;
    }}
}}
async function loadProgramSettings() {{
    const response = await fetch("/program-settings", {{cache:"no-store"}});
    if (!response.ok) return;
    const settings = await response.json();
    document.getElementById("programEnabled").checked = settings.enabled;
    document.getElementById("programRetention").value = String(settings.retention_days);
}}
document.getElementById("programSaveSettings").addEventListener("click", async () => {{
    const message = document.getElementById("programSettingsMessage");
    try {{
        const response = await fetch("/program-settings", {{
            method:"POST", headers:{{"Content-Type":"application/json"}},
            body:JSON.stringify({{
                enabled:document.getElementById("programEnabled").checked,
                retention_days:Number(document.getElementById("programRetention").value)
            }})
        }});
        if (!response.ok) throw new Error("Save failed");
        message.textContent = "Saved";
    }} catch(error) {{ message.textContent = error.message; }}
}});
programSearch.addEventListener("input", () => {{programPage=1;refreshProgramHistory();}});
programSort.addEventListener("change", () => {{programPage=1;refreshProgramHistory();}});
document.getElementById("programPrev").addEventListener("click", () => {{if(programPage>1) {{programPage--;refreshProgramHistory();}}}});
document.getElementById("programNext").addEventListener("click", () => {{if(programPage<programTotalPages) {{programPage++;refreshProgramHistory();}}}});
document.getElementById("programDownload").addEventListener("click", () => {{
    const params = new URLSearchParams({{search:programSearch.value,sort:programSort.value}});
    window.location.href = "/program-download?" + params;
}});
document.getElementById("logoutButton").addEventListener("click", async () => {{
    await fetch("/api/auth/logout", {{method:"POST"}});
    window.location.replace("/login");
}});
loadProgramSettings();
refreshProgramHistory();
setInterval(refreshProgramHistory, 15000);

renderLoggers();
loadNodes();
loadValues();

setInterval(refreshLoggers, 10000);
</script>
</body>
</html>
"""
        body = html.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_program_download(self, parsed):
        q = parse_qs(parsed.query)
        search = q.get("search", [""])[0]
        sort = q.get("sort", ["newest"])[0]
        try:
            self.controller.program_history.criteria(search, sort)
            rows = self.controller.program_history.export(search, sort)
        except ValueError:
            self.send_error(400, "Invalid export query")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="iox-program-history.csv"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b"timestamp,program_name,program_id,branch\r\n")
        for record in rows:
            buf = io.StringIO()
            writer = csv.writer(buf)
            # Prefix spreadsheet formula-leading text to avoid CSV injection.
            values = [str(x) for x in record]
            values = [("'" + v) if v.lstrip().startswith(("=", "+", "-", "@")) else v for v in values]
            writer.writerow(values)
            self.wfile.write(buf.getvalue().encode("utf-8"))

    def handle_auth_post(self, path):
        if not self.valid_request_origin():
            self.send_error(403, "Invalid origin")
            return
        try:
            data = self.read_json_request()
            with AUTH_LOCK:
                if path == "/api/auth/login":
                    ip = self.client_address[0]
                    if not login_allowed(ip):
                        self.send_error(429, "Too many login attempts")
                        return
                    creds = read_credentials(AUTH_BASE)
                    if creds is None or not isinstance(data.get("password"), str) or not check_password(data["password"], *creds):
                        record_login_failure(ip)
                        self.send_error(403, "Invalid credentials")
                        return
                    clear_login_failures(ip)
                    token = create_session()
                    self.send_response(204)
                    self.set_session_cookie(token)
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if path == "/api/auth/logout":
                    destroy_session(self.session_token())
                    self.send_response(204)
                    self.clear_session_cookie()
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                new = data.get("new_password")
                if not isinstance(new, str) or new != data.get("confirm_password"):
                    raise ValueError("Passwords do not match")
                if path == "/api/auth/setup":
                    if read_credentials(AUTH_BASE) is not None:
                        self.send_error(403, "Already configured")
                        return
                    create_initial_password(AUTH_BASE, new)
                elif path == "/api/auth/change":
                    if not validate_session(self.session_token()):
                        self.send_error(401)
                        return
                    change_password(AUTH_BASE, data.get("current_password", ""), new)
                elif path == "/api/auth/recover":
                    complete_recovery(AUTH_BASE, data.get("code", ""), new)
                destroy_all_sessions()
                self.send_response(204)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
        except (ValueError, TypeError, UnicodeError, AttributeError):
            self.send_error(400, "Invalid password request")
        except OSError:
            LOGGER.exception("Password update error")
            self.send_error(500, "Password update failed")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/api/auth/login", "/api/auth/logout", "/api/auth/setup", "/api/auth/change", "/api/auth/recover"):
            self.handle_auth_post(parsed.path)
            return
        if not self.valid_request_origin():
            self.send_error(403, "Invalid origin")
            return
        if not self.require_auth():
            return
        if parsed.path == "/program-settings":
            try:
                data = self.read_json_request()
                result = self.controller.program_history.configure(data)
                self.send_json(result)
            except (ValueError, TypeError):
                self.send_error(400, "Invalid program settings")
            return

        if parsed.path not in (
            "/add", "/delete", "/enable", "/interval",
            "/program-config"
        ):
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length).decode("utf-8"))

            if parsed.path == "/program-config":
                username = data.get("username", "admin")
                password = data.get("password", "")
                save_program_credentials(
                    AUTH_BASE, username, password
                )
                result = {"ok": True}
            elif parsed.path == "/add":
                entry = self.controller.add_logger(data)
                result = {
                    "ok": True,
                    "logger": entry,
                }
            elif parsed.path == "/enable":
                entry = self.controller.set_logger_enabled(data)
                result = {
                    "ok": True,
                    "logger": entry,
                }
            elif parsed.path == "/interval":
                entry = self.controller.set_logger_interval(data)
                result = {
                    "ok": True,
                    "logger": entry,
                }
            else:
                self.controller.delete_logger(data)
                result = {
                    "ok": True,
                }

            body = json.dumps(result).encode("utf-8")

            self.send_response(200)
            self.send_header(
                "Content-Type", "application/json; charset=utf-8"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        except Exception as exc:
            LOGGER.exception("WEB ADD LOGGER ERROR")
            body = json.dumps({
                "ok": False,
                "error": str(exc),
            }).encode("utf-8")

            self.send_response(400)
            self.send_header(
                "Content-Type", "application/json; charset=utf-8"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def send_graph(self, parsed):
        try:
            params = parse_qs(parsed.query)
            address = params.get("node", [None])[0]
            driver = params.get("driver", [None])[0]

            entry = self.controller.find_logger(
                address, driver, include_disabled=True
            )

            if entry is None:
                self.send_error(404, "Logger not found")
                return

            csv_file = self.controller.csv_path_for_logger(entry)

            archives = sorted(
                DATA_DIR.glob(f"{csv_file.stem}__*.csv")
            )

            files = archives[:]

            if csv_file.exists():
                files.append(csv_file)

            if not files:
                self.send_error(404, "CSV file not found")
                return

            points = []

            for file in files:
                with file.open(newline="") as f:
                    reader = csv.DictReader(f)

                    for row in reader:
                        raw = str(row.get("value", "")).strip()

                        # Accept the numeric part of values such as
                        # "698", "7.42", "31%", "-4.5 °F", etc.
                        match = re.search(
                            r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)",
                            raw,
                        )

                        if not match:
                            continue

                        try:
                            value = float(match.group(0))
                        except ValueError:
                            continue

                        timestamp = row.get("timestamp")

                        if timestamp:
                            points.append([timestamp, value])

            # Keep browser rendering reasonable even with many years
            # of retained samples.
            max_points = 5000

            if len(points) > max_points:
                step = len(points) / max_points
                points = [
                    points[int(i * step)]
                    for i in range(max_points)
                ]

            title = (
                f"{entry['node_name']} - {entry['value_name']}"
            )

            title_json = json.dumps(title)
            points_json = json.dumps(points)

            page = f"""<!doctype html>
<html>
<head>
<meta name="viewport"
      content="width=device-width, initial-scale=1">
<title>IoX Logger Graph</title>
<style>
* {{
  box-sizing: border-box;
}}

body {{
  margin: 0;
  padding: 22px;
  background: #f1f5f9;
  color: #1e293b;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
               Roboto, Arial, sans-serif;
}}

.card {{
  max-width: 1200px;
  margin: auto;
  padding: 22px;
  background: white;
  border: 1px solid #dbe3ec;
  border-radius: 10px;
  box-shadow: 0 2px 8px rgba(0,0,0,.08);
}}

h1 {{
  margin: 0 0 6px 0;
  color: #17365d;
  font-size: 22px;
}}

#summary {{
  margin-bottom: 18px;
  color: #64748b;
}}

.chart {{
  position: relative;
  width: 100%;
  height: 520px;
}}

canvas {{
  width: 100%;
  height: 100%;
}}

#empty {{
  display: none;
  padding: 50px 10px;
  text-align: center;
  color: #64748b;
}}

@media (max-width: 700px) {{
  body {{
    padding: 10px;
  }}

  .card {{
    padding: 14px;
  }}

  h1 {{
    font-size: 18px;
  }}

  .chart {{
    height: 380px;
  }}
}}
</style>
</head>
<body>
<div class="card">
  <h1 id="title"></h1>
  <div id="summary"></div>
  <div class="chart" id="chartArea">
    <canvas id="chart"></canvas>
  </div>
  <div id="empty">
    No numeric values are available to graph.
  </div>
</div>

<script>
const title = {title_json};
const points = {points_json};

document.getElementById("title").textContent = title;

if (!points.length) {{
  document.getElementById("chartArea").style.display = "none";
  document.getElementById("empty").style.display = "block";
}} else {{
  document.getElementById("summary").textContent =
    points.length + " retained samples";

  const canvas = document.getElementById("chart");
  const ctx = canvas.getContext("2d");

  function draw() {{
    const rect = canvas.getBoundingClientRect();
    const scale = window.devicePixelRatio || 1;

    canvas.width = Math.round(rect.width * scale);
    canvas.height = Math.round(rect.height * scale);

    ctx.setTransform(scale, 0, 0, scale, 0, 0);

    const width = rect.width;
    const height = rect.height;

    const margin = {{
      left: 62,
      right: 18,
      top: 20,
      bottom: 52
    }};

    const plotW = width - margin.left - margin.right;
    const plotH = height - margin.top - margin.bottom;

    const values = points.map(p => p[1]);

    let minY = Math.min(...values);
    let maxY = Math.max(...values);

    if (minY === maxY) {{
      minY -= 1;
      maxY += 1;
    }}

    const pad = (maxY - minY) * 0.05;
    minY -= pad;
    maxY += pad;

    ctx.clearRect(0, 0, width, height);

    ctx.font = "12px sans-serif";
    ctx.lineWidth = 1;

    // Horizontal grid and Y labels.
    for (let i = 0; i <= 5; i++) {{
      const y = margin.top + (plotH * i / 5);
      const value = maxY - ((maxY - minY) * i / 5);

      ctx.strokeStyle = "#e2e8f0";
      ctx.beginPath();
      ctx.moveTo(margin.left, y);
      ctx.lineTo(width - margin.right, y);
      ctx.stroke();

      ctx.fillStyle = "#64748b";
      ctx.textAlign = "right";
      ctx.textBaseline = "middle";
      ctx.fillText(
        value.toFixed(2).replace(/\\.00$/, ""),
        margin.left - 8,
        y
      );
    }}

    // Data line.
    ctx.strokeStyle = "#2563a6";
    ctx.lineWidth = 2;
    ctx.beginPath();

    points.forEach((point, i) => {{
      const x =
        margin.left +
        (points.length === 1
          ? plotW / 2
          : plotW * i / (points.length - 1));

      const y =
        margin.top +
        plotH * (maxY - point[1]) / (maxY - minY);

      if (i === 0) {{
        ctx.moveTo(x, y);
      }} else {{
        ctx.lineTo(x, y);
      }}
    }});

    ctx.stroke();

    // Start/end timestamps.
    const first = new Date(points[0][0]);
    const last = new Date(points[points.length - 1][0]);

    ctx.fillStyle = "#64748b";
    ctx.textBaseline = "top";

    ctx.textAlign = "left";
    ctx.fillText(
      first.toLocaleString(),
      margin.left,
      height - margin.bottom + 12
    );

    ctx.textAlign = "right";
    ctx.fillText(
      last.toLocaleString(),
      width - margin.right,
      height - margin.bottom + 12
    );
  }}

  draw();
  window.addEventListener("resize", draw);
}}
</script>
</body>
</html>
"""

            body = page.encode("utf-8")

            self.send_response(200)
            self.send_header(
                "Content-Type", "text/html; charset=utf-8"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        except Exception:
            LOGGER.exception("WEB GRAPH ERROR")
            self.send_error(500)

    def send_download(self, parsed):
        try:
            params = parse_qs(parsed.query)
            address = params.get("node", [None])[0]
            driver = params.get("driver", [None])[0]

            entry = self.controller.find_logger(
                address, driver, include_disabled=True
            )

            if entry is None:
                self.send_error(404, "Logger not found")
                return

            csv_file = self.controller.csv_path_for_logger(entry)

            # Retained archives are chronological by timestamped
            # filename. The active CSV is always newest.
            archives = sorted(
                DATA_DIR.glob(f"{csv_file.stem}__*.csv")
            )

            files = archives[:]

            if csv_file.exists():
                files.append(csv_file)

            if not files:
                self.send_error(404, "CSV file not found")
                return

            output = []

            for index, file in enumerate(files):
                lines = file.read_text().splitlines()

                if not lines:
                    continue

                if index == 0:
                    output.extend(lines)
                else:
                    # Every physical CSV has the same header.
                    output.extend(lines[1:])

            body = ("\n".join(output) + "\n").encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{self.controller.download_name_for_logger(entry)}"'
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        except Exception:
            LOGGER.exception("WEB DOWNLOAD ERROR")
            self.send_error(500)

    def send_loggers(self):
        import json

        try:
            with self.controller.logger_lock:
                loggers = [
                    entry.copy()
                    for entry in self.controller.configured_loggers
                ]

            for entry in loggers:
                csv_file = self.controller.csv_path_for_logger(entry)

                files = list(
                    DATA_DIR.glob(f"{csv_file.stem}__*.csv")
                )

                if csv_file.exists():
                    files.append(csv_file)

                entry["storage_bytes"] = sum(
                    file.stat().st_size
                    for file in files
                    if file.exists()
                )

            body = json.dumps(loggers).encode("utf-8")

            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/json; charset=utf-8"
            )
            self.send_header(
                "Content-Length",
                str(len(body))
            )
            self.end_headers()
            self.wfile.write(body)

        except Exception:
            LOGGER.exception("WEB LOGGERS ERROR")
            self.send_error(500)

    def send_values(self, parsed):
        import json

        try:
            params = parse_qs(parsed.query)
            address = params.get("node", [None])[0]

            if not address:
                self.send_error(400, "Missing node")
                return

            controller = self.controller

            node_xml = controller.isy_helper.cmd(
                f"/rest/nodes/{address}"
            )
            root = ET.fromstring(node_xml)

            node = root.find(".//node")
            family = node.find("family")

            if family is not None and family.get("instance"):
                slot = family.get("instance")
                labels = controller.get_driver_labels(slot, node.get('nodeDefId'))
            else:
                # Native IoX node: use its native node definition
                # to obtain friendly property names.
                nodedef_id = node.get("nodeDefId")
                labels = controller.get_native_driver_labels(
                    nodedef_id
                ) if nodedef_id else {}

            values = []
            seen_drivers = set()
            native_node = not (family is not None and family.get('instance'))

            if family is not None and family.get("instance") and node.get("nodeDefId"):
                for driver in controller.get_pg3_driver_ids(
                    slot, node.get("nodeDefId")
                ):
                    values.append({
                        "driver": driver,
                        "label": labels.get(driver, driver),
                        "formatted": None,
                        "value": None,
                    })
                    seen_drivers.add(driver)

            for prop in root.findall(".//property"):
                driver = prop.get("id")

                if not driver:
                    continue

                if driver in seen_drivers:
                    for entry in values:
                        if entry["driver"] == driver:
                            entry["formatted"] = prop.get("formatted")
                            entry["value"] = prop.get("value")
                            break
                    continue

                # For native nodes, expose only visible properties
                # declared by the node definition.
                if native_node and driver not in labels:
                    continue

                seen_drivers.add(driver)

                values.append({
                    "driver": driver,
                    "label": labels.get(driver, driver),
                    "formatted": prop.get("formatted"),
                    "value": prop.get("value"),
                })

            body = json.dumps(values).encode("utf-8")

            self.send_response(200)
            self.send_header(
                "Content-Type", "application/json; charset=utf-8"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        except Exception:
            LOGGER.exception("WEB VALUES ERROR")
            self.send_error(500)

    def log_message(self, format, *args):
        LOGGER.debug("WEB: " + format, *args)


class Controller(udi_interface.Node):
    id = "ioxloggertest"

    drivers = [
        {"driver": "ST", "value": 0, "uom": 2},
    ]

    def __init__(self, polyglot):
        super().__init__(polyglot, "controller", "controller", "IoX Logger")
        self.isy_helper = udi_interface.ISY(polyglot)
        self.logger_lock = threading.RLock()
        self.native_driver_labels = {}
        self.profile_definitions = {}
        self.program_isy = None
        self.program_listeners = []
        self.program_history = ProgramHistory(AUTH_BASE / "persist")

    def _start_program_monitor(self, isy):
        """Monitor individual IoX Then/Else executions."""
        from pyisy.programs.program import Program

        self.program_isy = isy

        count = 0
        for path, program in isy.programs:
            if not isinstance(program, Program):
                continue

            previous = [program.ran_then, program.ran_else]

            def on_event(status, p=program, prev=previous):
                then_count = p.ran_then
                else_count = p.ran_else

                if then_count > prev[0]:
                    try:
                        self.program_history.record(p.name, p.address, "THEN")
                    except Exception:
                        LOGGER.exception("Unable to record THEN execution")

                if else_count > prev[1]:
                    try:
                        self.program_history.record(p.name, p.address, "ELSE")
                    except Exception:
                        LOGGER.exception("Unable to record ELSE execution")

                prev[:] = [then_count, else_count]

            self.program_listeners.append(
                program.status_events.subscribe(on_event)
            )
            count += 1

        # Normalize legacy PyISY SOAP subscription HTTP headers.
        from pyisy import strings as pyisy_strings

        header = pyisy_strings.SUB_MSG["head"]
        header = header.replace("\r\n", "\n").replace("\r", "\n")
        header = "\r\n".join(header.split("\n"))
        pyisy_strings.SUB_MSG["head"] = header

        # Use the IoX SOAP event subscription format.
        pyisy_strings.SUB_MSG["head"] = (
            pyisy_strings.SUB_MSG["head"].replace(
                "X_Insteon_Lighting_Service:1",
                "X_IoX_Service:1",
            )
        )
        pyisy_strings.SUB_MSG["body"] = (
            pyisy_strings.SUB_MSG["body"]
            .replace(
                "X_Insteon_Lighting_Service:1",
                "X_IoX_Service:1",
            )
            .replace(
                "</duration>",
                "</duration><send>F</send>",
                1,
            )
        )

        # Use native IoX credentials only for event subscriptions.
        # REST requests retain their original eisy-ui connection.
        import base64

        credentials = read_program_credentials(AUTH_BASE)

        if credentials is None:
            LOGGER.warning(
                "Program monitor disabled: configure native IoX "
                "credentials in the HTML interface"
            )
            return

        username, password = credentials

        original_conn = isy.conn

        class ProgramMonitorConnection(type(original_conn)):
            @property
            def connection_info(self):
                info = super().connection_info

                auth = f"{username}:{password}".encode("utf-8")
                info["auth"] = base64.b64encode(auth).decode("ascii")
                info["passwd"] = password
                info["addr"] = "127.0.0.1"
                info["port"] = 8443
                info["tls"] = 1.2

                return info

        # Change only this instance's class. The underlying REST
        # connection fields and session remain unchanged.
        isy.conn.__class__ = ProgramMonitorConnection

        isy.auto_update = True
        LOGGER.info("Program monitor active: %d programs", count)

    def stop(self):
        if self.program_isy is not None:
            self.program_isy.auto_update = False
            self.program_isy = None
        self.program_listeners.clear()

        server = getattr(self, "web_server", None)
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                LOGGER.exception("Error shutting down HTTPS server")
            finally:
                try:
                    server.server_close()
                except Exception:
                    LOGGER.exception("Error closing HTTPS server")
                self.web_server = None

        LoggerWebHandler.controller = None

    def start(self):
        LOGGER.info("IoX Logger starting")

        for _ in range(20):
            if self.isy_helper.valid or self.isy_helper.unauthorized:
                break
            time.sleep(0.5)

        if self.isy_helper.unauthorized:
            LOGGER.error("Unrestricted ISY access is not authorized")
            return

        if not self.isy_helper.valid:
            LOGGER.error("IoX connection information was not received")
            return

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.configured_loggers = self.load_logger_config()

        try:
            self.load_native_driver_labels()
        except Exception:
            LOGGER.exception("Unable to load native IoX driver labels")
            self.native_driver_labels = {}

        LOGGER.info(
            "Loaded %d configured logger(s)",
            len(self.configured_loggers),
        )

        LoggerWebHandler.controller = self

        try:
            cert_file, key_file = ensure_certificate(
                Path(__file__).resolve().parent
            )

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert_file, key_file)

            self.web_server = LoggerHTTPSServer(
                ("0.0.0.0", 8765),
                LoggerWebHandler,
                context,
            )
            threading.Thread(
                target=self.web_server.serve_forever,
                name="LoggerWeb",
                daemon=True,
            ).start()
            LOGGER.info("Logger web interface listening on port 8765")
        except Exception:
            LOGGER.exception("Unable to start logger web interface")

        # Diagnostic: catalog all Node Server nodes in IoX
        try:
            isy = self.isy_helper.pyisy()

            catalog = {}

            for path, node in isy.nodes:
                slot = getattr(node, "node_server", None)
                nodedef = getattr(node, "node_def_id", None)

                if slot is None:
                    # Native IoX device.  Exclude scenes/groups and
                    # other entries that do not have a node definition.
                    if not nodedef:
                        continue
                    source = "native"
                else:
                    source = str(slot)

                catalog.setdefault(source, []).append({
                    "name": node.name,
                    "address": node.address,
                    "nodedef": nodedef,
                })

            def source_sort_key(source):
                if source == "native":
                    return (0, 0)
                return (1, int(source))

            for source in sorted(catalog, key=source_sort_key):
                LOGGER.info("CATALOG SOURCE %s", source)

                for item in sorted(
                    catalog[source],
                    key=lambda x: x["name"].lower(),
                ):
                    LOGGER.info(
                        "CATALOG NODE source=%s name=%r "
                        "address=%r nodedef=%r",
                        source,
                        item["name"],
                        item["address"],
                        item["nodedef"],
                    )

            LOGGER.info(
                "CATALOG COMPLETE sources=%d nodes=%d",
                len(catalog),
                sum(len(nodes) for nodes in catalog.values()),
            )

            self.web_catalog = {}

            for source in sorted(catalog, key=source_sort_key):
                nodes = catalog[source]

                if source == "native":
                    source_name = "IoX / Native"
                else:
                    controller_nodes = [
                        n for n in nodes
                        if n["address"] == (
                            f"n{int(source):03d}_controller"
                        )
                    ]

                    if controller_nodes:
                        source_name = controller_nodes[0]["name"]
                    else:
                        source_name = f"Slot {source}"

                self.web_catalog[source] = {
                    "source_name": source_name,
                    "nodes": nodes,
                }

            self.refresh_logger_metadata()

            try:
                self._start_program_monitor(isy)
            except Exception:
                LOGGER.exception("Unable to start program monitor")


        except Exception:
            LOGGER.exception("CATALOG ERROR")

        self.setDriver("ST", 1)

        threading.Thread(
            target=self.logging_loop,
            name="LoggerScheduler",
            daemon=True,
        ).start()

    def get_driver_labels(self, slot, nodedef_id=None):
        """Return cached friendly driver labels for a PG3x node."""
        nodedef = self.profile_definitions.get(
            ("10", str(slot), nodedef_id), {}
        )

        return {
            prop["id"]: prop.get("name") or prop["id"]
            for prop in nodedef.get("properties", [])
            if prop.get("id") and not prop.get("hide", False)
        }

    def get_pg3_driver_ids(self, slot, nodedef_id):
        """Return cached status driver IDs for a PG3x node."""
        nodedef = self.profile_definitions.get(
            ("10", str(slot), nodedef_id), {}
        )

        return [
            prop["id"]
            for prop in nodedef.get("properties", [])
            if prop.get("id") and not prop.get("hide", False)
        ]

    def load_native_driver_labels(self):
        """Cache IoX profile definitions for native and PG3x nodes."""
        import json

        raw = self.isy_helper.cmd(
            "/rest/profiles?include=nodedefs,editors,linkdefs"
        )
        data = json.loads(raw)

        profiles = {}
        native_labels = {}

        for family in data.get("families", []):
            family_id = str(family.get("id", ""))

            for instance in family.get("instances", []):
                instance_id = str(instance.get("id", ""))

                for nodedef in instance.get("nodedefs", []):
                    nodedef_id = nodedef.get("id")
                    if not nodedef_id:
                        continue

                    key = (family_id, instance_id, nodedef_id)
                    profiles[key] = nodedef

                    if family_id == "10":
                        continue

                    labels = {}
                    for prop in nodedef.get("properties", []):
                        if prop.get("hide", False):
                            continue
                        driver = prop.get("id")
                        if driver:
                            labels[driver] = prop.get("name") or driver

                    native_labels[nodedef_id] = labels

        self.profile_definitions = profiles
        self.native_driver_labels = native_labels

        LOGGER.info(
            "Loaded %d profile definitions and %d native label sets",
            len(profiles), len(native_labels),
        )

    def get_native_driver_labels(self, nodedef_id):
        """Return cached native IoX driver labels."""
        return self.native_driver_labels.get(nodedef_id, {})

    def refresh_logger_metadata(self):
        """Refresh friendly names without changing logger identity."""
        node_index = {}

        for slot, source in self.web_catalog.items():
            for node in source["nodes"]:
                node_index[node["address"]] = {
                    "slot": slot,
                    "source_name": source["source_name"],
                    "node_name": node["name"],
                    "nodedef": node.get("nodedef"),
                }

        with self.logger_lock:
            loggers = [
                entry.copy()
                for entry in self.configured_loggers
            ]

        label_cache = {}
        updates = []

        for entry in loggers:
            address = entry["node_address"]
            info = node_index.get(address)

            if info is None:
                continue

            slot = info["slot"]

            if slot == "native":
                nodedef_id = info.get("nodedef")
                cache_key = ("native", nodedef_id)

                if cache_key not in label_cache:
                    try:
                        label_cache[cache_key] = (
                            self.get_native_driver_labels(nodedef_id)
                            if nodedef_id else {}
                        )
                    except Exception:
                        LOGGER.exception(
                            "Unable to load native driver labels for %s",
                            nodedef_id,
                        )
                        label_cache[cache_key] = {}

                labels = label_cache[cache_key]

            else:
                nodedef_id = info.get("nodedef")
                cache_key = (slot, nodedef_id)

                if cache_key not in label_cache:
                    try:
                        label_cache[cache_key] = self.get_driver_labels(
                            slot, nodedef_id
                        )
                    except Exception:
                        LOGGER.exception(
                            "Unable to load driver labels for %s",
                            cache_key,
                        )
                        label_cache[cache_key] = {}

                labels = label_cache[cache_key]

            driver = entry["driver"]

            updates.append({
                "node_address": address,
                "driver": driver,
                "source_name": info["source_name"],
                "node_name": info["node_name"],
                "value_name": labels.get(
                    driver,
                    entry["value_name"],
                ),
            })

        changed = False

        with self.logger_lock:
            for update in updates:
                entry = self.find_logger(
                    update["node_address"],
                    update["driver"],
                    include_disabled=True,
                )

                if entry is None:
                    continue

                for key in (
                    "source_name",
                    "node_name",
                    "value_name",
                ):
                    if entry.get(key) != update[key]:
                        LOGGER.info(
                            "Logger metadata changed: %s: %s -> %s",
                            key,
                            entry.get(key),
                            update[key],
                        )
                        entry[key] = update[key]
                        changed = True

            if changed:
                self.save_logger_config()

        return changed

    def load_logger_config(self):
        if not CONFIG_FILE.exists():
            return []

        try:
            with CONFIG_FILE.open("r") as f:
                data = json.load(f)

            return data if isinstance(data, list) else []

        except Exception:
            LOGGER.exception("Unable to load logger configuration")
            return []

    def save_logger_config(self):
        temp = CONFIG_FILE.with_suffix(".tmp")

        config_fields = (
            "source_name",
            "node_address",
            "node_name",
            "driver",
            "value_name",
            "interval",
            "enabled",
        )

        persistent_config = [
            {
                key: entry[key]
                for key in config_fields
                if key in entry
            }
            for entry in self.configured_loggers
        ]

        with temp.open("w") as f:
            json.dump(persistent_config, f, indent=2)

        temp.replace(CONFIG_FILE)

    def add_logger(self, data):
        with self.logger_lock:
            required = (
                "source_name",
                "node_address",
                "node_name",
                "driver",
                "value_name",
                "interval",
            )

            for key in required:
                if key not in data:
                    raise ValueError(f"Missing {key}")

            entry = {
                "source_name": str(data["source_name"]),
                "node_address": str(data["node_address"]),
                "node_name": str(data["node_name"]),
                "driver": str(data["driver"]),
                "value_name": str(data["value_name"]),
                "interval": int(data["interval"]),
                "enabled": True,
            }

            if entry["interval"] != 0 and entry["interval"] < 60:
                raise ValueError(
                    "Interval must be On Change or at least 60 seconds"
                )

            if self.find_logger(
                entry["node_address"],
                entry["driver"],
                include_disabled=True,
            ) is not None:
                raise ValueError(
                    "A logger for this node and value already exists"
                )

            self.configured_loggers.append(entry)
            self.save_logger_config()

            if hasattr(self, "next_run"):
                self.next_run.pop(
                    (entry["node_address"], entry["driver"]),
                    None,
                )

            LOGGER.info(
                "Configured logger: %s - %s every %s seconds",
                entry["node_name"],
                entry["value_name"],
                entry["interval"],
            )

            return entry

    def find_logger(
        self, node_address, driver, include_disabled=False
    ):
        with self.logger_lock:
            for entry in self.configured_loggers:
                if (
                    entry.get("node_address") == node_address
                    and entry.get("driver") == driver
                ):
                    if include_disabled or entry.get("enabled", True):
                        return entry

        return None

    def csv_path_for_logger(self, entry):
        safe_address = "".join(
            c if c.isalnum() else "_"
            for c in entry["node_address"]
        ).strip("_")

        safe_driver = "".join(
            c if c.isalnum() else "_"
            for c in entry["driver"]
        ).strip("_")

        return DATA_DIR / (
            f"{safe_address}__{safe_driver}.csv"
        )

    def download_name_for_logger(self, entry):
        safe_node = "".join(
            c if c.isalnum() else "_"
            for c in entry["node_name"]
        ).strip("_")

        safe_value = "".join(
            c if c.isalnum() else "_"
            for c in entry["value_name"]
        ).strip("_")

        return f"{safe_node}__{safe_value}.csv"

    def delete_logger(self, data):
        with self.logger_lock:
            address = str(data.get("node_address", ""))
            driver = str(data.get("driver", ""))

            entry = self.find_logger(
                address, driver, include_disabled=True
            )

            if entry is None:
                raise ValueError("Logger not found")

            # Delete the active CSV and all rotated archives belonging
            # to this logger before removing its configuration.
            csv_file = self.csv_path_for_logger(entry)

            files = list(
                DATA_DIR.glob(f"{csv_file.stem}__*.csv")
            )

            if csv_file.exists():
                files.append(csv_file)

            deleted_files = 0
            deleted_bytes = 0

            for file in files:
                try:
                    size = file.stat().st_size
                    file.unlink()
                    deleted_files += 1
                    deleted_bytes += size
                except FileNotFoundError:
                    pass

            self.configured_loggers.remove(entry)
            self.save_logger_config()

            if hasattr(self, "next_run"):
                self.next_run.pop(
                    (entry["node_address"], entry["driver"]),
                    None,
                )

            LOGGER.info(
                "Deleted logger and historical data: %s - %s "
                "(%d files, %d bytes)",
                entry["node_name"],
                entry["value_name"],
                deleted_files,
                deleted_bytes,
            )

    def set_logger_interval(self, data):
        with self.logger_lock:
            address = str(data.get("node_address", ""))
            driver = str(data.get("driver", ""))

            try:
                interval = int(data.get("interval"))
            except (TypeError, ValueError):
                raise ValueError("Invalid interval")

            if interval != 0 and interval < 60:
                raise ValueError(
                    "Interval must be On Change or at least 60 seconds"
                )

            entry = self.find_logger(
                address, driver, include_disabled=True
            )

            if entry is None:
                raise ValueError("Logger not found")

            entry["interval"] = interval
            entry.pop("last_observed", None)

            self.save_logger_config()

            if hasattr(self, "next_run"):
                self.next_run.pop(
                    (entry["node_address"], entry["driver"]),
                    None,
                )

            LOGGER.info(
                "Updated logger interval: %s - %s = %s",
                entry["node_name"],
                entry["value_name"],
                (
                    "On Change (5 sec polling)"
                    if interval == 0
                    else f"{interval} seconds"
                ),
            )

            return entry

    def set_logger_enabled(self, data):
        with self.logger_lock:
            address = str(data.get("node_address", ""))
            driver = str(data.get("driver", ""))
            enabled = bool(data.get("enabled"))

            entry = self.find_logger(
                address, driver, include_disabled=True
            )

            if entry is None:
                raise ValueError("Logger not found")

            entry["enabled"] = enabled

            if enabled:
                entry.pop("last_observed", None)

            self.save_logger_config()

            if hasattr(self, "next_run"):
                self.next_run.pop(
                    (entry["node_address"], entry["driver"]),
                    None,
                )

            LOGGER.info(
                "%s logger: %s - %s",
                "Enabled" if enabled else "Disabled",
                entry["node_name"],
                entry["value_name"],
            )

            return entry

    def logging_loop(self):
        """Single scheduler for all configured loggers."""
        self.next_run = {}

        while True:
            now = time.monotonic()

            try:
                with self.logger_lock:
                    due_loggers = []

                    for entry in self.configured_loggers:
                        if not entry.get("enabled", True):
                            continue

                        key = (
                            entry["node_address"],
                            entry["driver"],
                        )

                        due = self.next_run.get(key, 0)

                        if now >= due:
                            due_loggers.append(
                                (entry.copy(), key)
                            )

                for entry, key in due_loggers:
                    try:
                        self.log_value(entry)
                    except Exception:
                        LOGGER.exception(
                            "Error logging %s - %s",
                            entry.get("node_name"),
                            entry.get("value_name"),
                        )

                    with self.logger_lock:
                        current = self.find_logger(
                            key[0],
                            key[1],
                            include_disabled=True,
                        )

                        if current is not None and current.get(
                            "enabled", True
                        ):
                            interval = int(current["interval"])
                            poll_seconds = 5 if interval == 0 else interval

                            self.next_run[key] = (
                                time.monotonic() + poll_seconds
                            )

            except Exception:
                LOGGER.exception("Generic logger scheduler error")

            time.sleep(1)

    def rotate_csv_if_needed(self, entry):
        """Rotate a logger CSV and enforce its total storage limit."""
        csv_file = self.csv_path_for_logger(entry)

        if not csv_file.exists():
            return

        # Rotate the active file when it reaches the size limit.
        if csv_file.stat().st_size >= CSV_ROTATE_BYTES:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive = csv_file.with_name(
                f"{csv_file.stem}__{timestamp}.csv"
            )
            csv_file.rename(archive)

            LOGGER.info(
                "Rotated logger CSV %s -> %s",
                csv_file.name,
                archive.name,
            )

        # Keep only enough rotated files to remain within the
        # per-logger storage allowance.
        max_archives = max(
            0,
            (LOGGER_MAX_BYTES // CSV_ROTATE_BYTES) - 1,
        )

        archives = sorted(
            DATA_DIR.glob(f"{csv_file.stem}__*.csv"),
            key=lambda file: file.stat().st_mtime,
        )

        while len(archives) > max_archives:
            oldest = archives.pop(0)
            oldest.unlink()

            LOGGER.info(
                "Deleted old logger archive %s to enforce storage limit",
                oldest.name,
            )

    def enforce_global_storage_limit(self):
        """Keep total logger CSV storage within the plugin limit."""
        files = list(DATA_DIR.glob("*.csv"))

        total_size = sum(
            file.stat().st_size
            for file in files
            if file.exists()
        )

        if total_size <= PLUGIN_MAX_BYTES:
            return

        # Rotated archives contain "__" after the stable
        # node-address/driver filename stem. Active CSVs do not.
        archives = []

        for file in files:
            stem = file.stem

            # Stable active names end in __DRIVER. Archives have
            # an additional __timestamp suffix.
            if stem.count("__") >= 2:
                archives.append(file)

        archives.sort(key=lambda file: file.stat().st_mtime)

        while total_size > PLUGIN_MAX_BYTES and archives:
            oldest = archives.pop(0)

            if not oldest.exists():
                continue

            size = oldest.stat().st_size
            oldest.unlink()
            total_size -= size

            LOGGER.warning(
                "Deleted old logger archive %s to enforce "
                "global CSV storage limit",
                oldest.name,
            )

    def log_value(self, entry):
        address = entry["node_address"]
        driver = entry["driver"]

        xml = self.isy_helper.cmd(
            f"/rest/nodes/{address}"
        )
        root = ET.fromstring(xml)

        prop = root.find(
            f".//property[@id='{driver}']"
        )

        if prop is None:
            raise RuntimeError(
                f"{driver} not found on {address}"
            )

        value = prop.get("formatted") or prop.get("value")
        timestamp = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

        if int(entry["interval"]) == 0:
            with self.logger_lock:
                current = self.find_logger(
                    address,
                    driver,
                    include_disabled=True,
                )

                if current is None:
                    return

                previous = current.get("last_observed")
                current["latest_value"] = value
                current["last_observed"] = value

            # First observation establishes the baseline.
            # Subsequent identical values are not written.
            if previous is None or previous == value:
                return

        csv_file = self.csv_path_for_logger(entry)

        self.rotate_csv_if_needed(entry)
        self.enforce_global_storage_limit()

        new_file = not csv_file.exists()

        with csv_file.open("a", newline="") as f:
            writer = csv.writer(f)

            if new_file:
                writer.writerow([
                    "timestamp",
                    "value",
                    "node_address",
                    "driver",
                ])

            writer.writerow([
                timestamp,
                value,
                address,
                driver,
            ])

        with self.logger_lock:
            current = self.find_logger(
                address,
                driver,
                include_disabled=True,
            )

            if current is not None:
                current["latest_value"] = value
                current["last_sample"] = timestamp

        LOGGER.info(
            "Logged %s - %s: %s",
            entry["node_name"],
            entry["value_name"],
            value,
        )


if __name__ == "__main__":
    polyglot.start("1.1.2")

    controller = Controller(polyglot)
    polyglot.addNode(controller)

    configuration_help = "./configdoc.md"

    if Path(configuration_help).is_file():
        cfgdoc = markdown2.markdown_path(configuration_help)
        polyglot.setCustomParamsDoc(cfgdoc)

    polyglot.ready()
    polyglot.updateProfile()

    controller.start()

    polyglot.runForever()
