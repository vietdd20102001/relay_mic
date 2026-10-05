#!/usr/bin/env python3
# Telegram alert relay - chi dung thu vien chuan, tuong thich Python 3.6+
import hmac
import html
import json
import logging
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

ICONS = {"critical": "🔴", "warning": "🟠", "info": "🟢"}

CFG = {}
LAST_SENT = {}
LOCK = threading.Lock()
OPENER = None


def load_config(path):
    global OPENER
    with open(path, "r", encoding="utf-8") as f:
        CFG.update(json.load(f))
    CFG.setdefault("listen_host", "0.0.0.0")
    CFG.setdefault("listen_port", 8080)
    CFG.setdefault("cooldown_seconds", 0)
    CFG.setdefault("severity_route", {})
    CFG.setdefault("host_route", {})
    proxy = CFG.get("proxy", "")
    if proxy:
        OPENER = urllib.request.build_opener(
            urllib.request.ProxyHandler({"https": proxy, "http": proxy}))
    else:
        OPENER = urllib.request.build_opener()


def is_duplicate(key):
    cd = CFG["cooldown_seconds"]
    if cd <= 0:
        return False
    now = time.time()
    with LOCK:
        for k in [k for k, t in LAST_SENT.items() if now - t > cd]:
            del LAST_SENT[k]
        if key in LAST_SENT:
            return True
        LAST_SENT[key] = now
        return False


def send_telegram(chat_id, text):
    url = "https://api.telegram.org/bot%s/sendMessage" % CFG["bot_token"]
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
    }).encode("utf-8")
    req = urllib.request.Request(url, data=data)
    with OPENER.open(req, timeout=15) as resp:
        resp.read()


class Handler(BaseHTTPRequestHandler):
    server_version = "tg-relay"

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.client_address[0], fmt % args)

    def reply(self, code, body):
        data = (body + "\n").encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self.reply(200, "ok")
        else:
            self.reply(404, "not found")

    def do_POST(self):
        if self.path != "/alert":
            return self.reply(404, "not found")

        key = self.headers.get("X-API-Key", "")
        if not hmac.compare_digest(key.encode(), CFG["api_key"].encode()):
            return self.reply(401, "unauthorized")

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 65536:
            return self.reply(400, "bad request")

        body = self.rfile.read(length).decode("utf-8", "replace")
        form = urllib.parse.parse_qs(body, keep_blank_values=True)

        def field(name, default=""):
            v = form.get(name)
            return v[0] if v else default

        host = field("host", "unknown") or "unknown"
        sev = field("severity", "info").lower()
        if sev not in ICONS:
            sev = "info"
        msg = field("message")
        if len(msg) > 3500:
            msg = msg[:3500] + "..."

        if is_duplicate("%s|%s|%s" % (host, sev, msg)):
            return self.reply(200, "skipped (cooldown)")

        chats = (CFG["host_route"].get(host)
                 or CFG["severity_route"].get(sev)
                 or CFG["severity_route"].get("info")
                 or [])
        if not chats:
            return self.reply(500, "no chat configured")

        text = "%s <b>[%s] %s</b>\n%s\n<i>%s</i>" % (
            ICONS[sev], sev.upper(), html.escape(host),
            html.escape(msg), time.strftime("%Y-%m-%d %H:%M:%S"))

        ok = 0
        for chat in chats:
            try:
                send_telegram(chat, text)
                ok += 1
            except Exception as e:
                logging.error("gui chat %s loi: %s", chat, e)

        if ok == 0:
            return self.reply(502, "send failed")
        logging.info("OK host=%s sev=%s -> %d/%d chat", host, sev, ok, len(chats))
        self.reply(200, "ok")


class ThreadedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    path = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    load_config(path)
    addr = (CFG["listen_host"], int(CFG["listen_port"]))
    logging.info("tg-relay listen %s:%s", *addr)
    ThreadedServer(addr, Handler).serve_forever()


if __name__ == "__main__":
    main()