"""Small dependency-free web server for the Cold Box dashboard."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import subprocess
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from cold_box_room.ui.state import case_snapshot, health, list_cases

STATIC_DIR = Path(__file__).with_name("static")
ACTIVE_RUNS: dict[str, subprocess.Popen[str]] = {}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "ColdBoxUI/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        if os.environ.get("COLD_BOX_UI_LOG", "").lower() in {"1", "true", "yes"}:
            super().log_message(format, *args)

    def _json(self, payload: Any, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path) -> None:
        if not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        content_type, _ = mimetypes.guess_type(str(path))
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path == "/api/health":
            self._json(health())
            return
        if path == "/api/cases":
            self._json({"cases": list_cases()})
            return
        if path.startswith("/api/cases/"):
            remainder = path.removeprefix("/api/cases/").strip("/")
            if "/artifacts/" in remainder:
                case_id, artifact = remainder.split("/artifacts/", 1)
                try:
                    snapshot = case_snapshot(case_id)
                    case_dir = Path(snapshot["records_dir"]).resolve()
                    target = (case_dir / artifact).resolve()
                    target.relative_to(case_dir)
                    if not target.is_file():
                        raise FileNotFoundError(f"Artifact not available in this case bundle: {artifact}")
                    self._json({
                        "case_id": case_id,
                        "artifact": artifact,
                        "content": target.read_text(encoding="utf-8", errors="replace")[:250000],
                    })
                except (FileNotFoundError, ValueError, OSError) as exc:
                    self._json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
                return
            case_id = remainder
            try:
                self._json(case_snapshot(case_id))
            except (FileNotFoundError, ValueError) as exc:
                self._json({"ok": False, "error": str(exc)}, HTTPStatus.NOT_FOUND)
            return
        if path in {"/", "/index.html"}:
            self._file(STATIC_DIR / "index.html")
            return
        static_path = (STATIC_DIR / path.lstrip("/")).resolve()
        try:
            static_path.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self._file(static_path)

    def do_POST(self) -> None:
        if self.path != "/api/investigations":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            case_id = str(payload.get("case_id") or "").strip()
            evidence = Path(str(payload.get("evidence") or "")).expanduser().resolve()
            goal = str(payload.get("goal") or "").strip()
            model = str(payload.get("model") or "").strip()
            if not case_id or ".." in case_id or "/" in case_id or "\\" in case_id:
                raise ValueError("Enter a simple case ID using letters, numbers, dashes, or underscores.")
            if not evidence.exists():
                raise ValueError(f"Evidence path does not exist: {evidence}")
            if case_id in ACTIVE_RUNS and ACTIVE_RUNS[case_id].poll() is None:
                raise ValueError(f"Case {case_id!r} is already running.")

            from cold_box_room.r1.paths import get_records_root
            records_root = get_records_root()
            case_dir = records_root / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            log_path = case_dir / "hallway_run.log"

            cmd = [
                sys.executable, "-m", "cold_box_room.e2e.run_hallway",
                "--run-id", case_id, "--case-id", case_id, "--evidence", str(evidence),
            ]
            if model:
                cmd += ["--model", model]
            if goal:
                cmd += ["--layer1-goal", goal, "--room3-goal", goal]

            # Pass records root explicitly so the subprocess writes where the UI reads.
            env = dict(os.environ)
            env["COLD_BOX_ROOM_RECORDS"] = str(records_root)

            log_file = open(log_path, "w")  # noqa: SIM115 — stays open for subprocess lifetime
            try:
                process = subprocess.Popen(
                    cmd,
                    cwd=str(Path(__file__).resolve().parents[2]),
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                    env=env,
                )
            except Exception:
                log_file.close()
                raise
            ACTIVE_RUNS[case_id] = process
            self._json({"ok": True, "case_id": case_id, "pid": process.pid, "log": "hallway_run.log"}, HTTPStatus.ACCEPTED)
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            self._json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)


def start_ui_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = False,
    case_id: str = "",
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    threading.Thread(target=server.serve_forever, daemon=True, name="cold-box-ui").start()
    if open_browser:
        suffix = f"/?case={case_id}" if case_id else ""
        threading.Timer(0.4, lambda: webbrowser.open(f"http://{host}:{port}{suffix}")).start()
    return server


def run_ui(*, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    url = f"http://{host}:{port}"
    print(f"Cold Box dashboard: {url}", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cold Box investigation dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true")
    args = parser.parse_args(argv)
    run_ui(host=args.host, port=args.port, open_browser=not args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
