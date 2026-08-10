#!/usr/bin/env python3
"""HTTP file store with permanent capability keys."""

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import secrets
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


class Server:
    def __init__(self, host, port, api_token_file_obj="NOTOKEN"):
        self.host = host
        self.port = port
        self.root = Path("filestore").resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.root / ".filestore.json"
        self.lock = threading.RLock()

        # "NOTOKEN" or None disables API-token authentication.
        # Otherwise this can be a readable file object or a path.
        self.api_token = None
        if api_token_file_obj not in ("NOTOKEN", None):
            if hasattr(api_token_file_obj, "read"):
                self.api_token = api_token_file_obj.read().strip()
            else:
                with open(api_token_file_obj, "r", encoding="utf-8") as f:
                    self.api_token = f.read().strip()
            if not self.api_token:
                raise ValueError("API token file/object is empty")

        self.metadata = self._load_metadata()
        self._repair_metadata()
        self.httpd = ThreadingHTTPServer(
            (self.host, self.port), self._make_handler()
        )

    def _load_metadata(self):
        if not self.metadata_file.exists():
            return {"files": {}, "folders": {}}
        with open(self.metadata_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("files", {})
        data.setdefault("folders", {})
        return data

    def _save_metadata(self):
        tmp = self.metadata_file.with_name(".filestore.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2, sort_keys=True)
            f.write("\n")
        tmp.replace(self.metadata_file)

    def _repair_metadata(self):
        changed = False
        with self.lock:
            for path in self.root.rglob("*"):
                if path == self.metadata_file or path.name == ".filestore.json.tmp":
                    continue
                rel = self._relative(path)
                if path.is_file() and rel not in self.metadata["files"]:
                    self.metadata["files"][rel] = self._new_file_metadata()
                    changed = True
                elif path.is_dir() and rel not in self.metadata["folders"]:
                    self.metadata["folders"][rel] = self._new_folder_metadata()
                    changed = True
            if changed:
                self._save_metadata()

    @staticmethod
    def _new_key():
        return secrets.token_urlsafe(32)

    def _new_file_metadata(self):
        return {
            "read_key": self._new_key(),
            "edit_key": self._new_key(),
            "delete_key": self._new_key(),
            "rename_key": self._new_key(),
        }

    def _new_folder_metadata(self):
        return {
            "edit_key": self._new_key(),
            "delete_key": self._new_key(),
            "rename_key": self._new_key(),
        }

    def _clean_path(self, path):
        path = unquote(path or "").replace("\\", "/").lstrip("/")
        if "\x00" in path:
            raise ValueError("Invalid path")
        candidate = (self.root / path).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Path traversal is not allowed") from exc
        if candidate == self.root:
            raise ValueError("The root is not a file or folder")
        return candidate

    def _relative(self, path):
        return str(path.resolve().relative_to(self.root)).replace("\\", "/")

    @staticmethod
    def _check_key(metadata, key_name, supplied):
        expected = metadata.get(key_name)
        return bool(
            expected and supplied and secrets.compare_digest(expected, supplied)
        )

    @staticmethod
    def _result(operation, path, metadata, **extra):
        result = {
            "success": True,
            "operation": operation,
            "path": path,
            "keys": dict(metadata),
        }
        result.update(metadata)
        result.update(extra)
        return result

    def upload_file(self, relative_path, data):
        with self.lock:
            path = self._clean_path(relative_path)
            key = self._relative(path)
            if path.exists():
                raise FileExistsError("File or folder already exists")
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                f.write(data)
            metadata = self._new_file_metadata()
            self.metadata["files"][key] = metadata
            self._save_metadata()
            return self._result("upload", key, metadata)

    def read_file(self, relative_path, read_key=None):
        with self.lock:
            path = self._clean_path(relative_path)
            key = self._relative(path)
            metadata = self.metadata["files"].get(key)
            if metadata is None or not path.is_file():
                raise FileNotFoundError("File does not exist")
            if read_key is not None and not self._check_key(
                metadata, "read_key", read_key
            ):
                raise PermissionError("Invalid read key")
            return path.read_bytes(), metadata

    def edit_file(self, relative_path, edit_key, data):
        with self.lock:
            path = self._clean_path(relative_path)
            key = self._relative(path)
            metadata = self.metadata["files"].get(key)
            if metadata is None or not path.is_file():
                raise FileNotFoundError("File does not exist")
            if not self._check_key(metadata, "edit_key", edit_key):
                raise PermissionError("Invalid edit key")
            with open(path, "wb") as f:
                f.write(data)
            return self._result("edit", key, metadata)

    def delete_file(self, relative_path, delete_key):
        with self.lock:
            path = self._clean_path(relative_path)
            key = self._relative(path)
            metadata = self.metadata["files"].get(key)
            if metadata is None or not path.is_file():
                raise FileNotFoundError("File does not exist")
            if not self._check_key(metadata, "delete_key", delete_key):
                raise PermissionError("Invalid delete key")
            path.unlink()
            del self.metadata["files"][key]
            self._save_metadata()
            return self._result("delete", key, metadata)

    def rename_file(self, relative_path, rename_key, new_name):
        with self.lock:
            path = self._clean_path(relative_path)
            old_key = self._relative(path)
            metadata = self.metadata["files"].get(old_key)
            if metadata is None or not path.is_file():
                raise FileNotFoundError("File does not exist")
            if not self._check_key(metadata, "rename_key", rename_key):
                raise PermissionError("Invalid rename key")
            if (
                not new_name
                or new_name in (".", "..")
                or "/" in new_name
                or "\\" in new_name
            ):
                raise ValueError("new_name must be a single filename")
            new_path = path.parent / new_name
            if new_path.exists():
                raise FileExistsError(
                    "A file or folder with that name already exists"
                )
            path.rename(new_path)
            new_key = self._relative(new_path)
            del self.metadata["files"][old_key]
            self.metadata["files"][new_key] = metadata
            self._save_metadata()
            return self._result(
                "rename", new_key, metadata,
                old_path=old_key, new_path=new_key
            )

    def create_folder(self, relative_path):
        with self.lock:
            path = self._clean_path(relative_path)
            key = self._relative(path)
            if path.exists():
                raise FileExistsError("File or folder already exists")
            path.mkdir(parents=True)
            metadata = self._new_folder_metadata()
            self.metadata["folders"][key] = metadata
            self._save_metadata()
            return self._result("create_folder", key, metadata)

    def edit_folder(self, relative_path, edit_key):
        with self.lock:
            path = self._clean_path(relative_path)
            key = self._relative(path)
            metadata = self.metadata["folders"].get(key)
            if metadata is None or not path.is_dir():
                raise FileNotFoundError("Folder does not exist")
            if not self._check_key(metadata, "edit_key", edit_key):
                raise PermissionError("Invalid folder edit key")
            return self._result("edit_folder", key, metadata)

    def rename_folder(self, relative_path, rename_key, new_name):
        with self.lock:
            path = self._clean_path(relative_path)
            old_key = self._relative(path)
            metadata = self.metadata["folders"].get(old_key)
            if metadata is None or not path.is_dir():
                raise FileNotFoundError("Folder does not exist")
            if not self._check_key(metadata, "rename_key", rename_key):
                raise PermissionError("Invalid folder rename key")
            if (
                not new_name
                or new_name in (".", "..")
                or "/" in new_name
                or "\\" in new_name
            ):
                raise ValueError("new_name must be a single folder name")
            new_path = path.parent / new_name
            if new_path.exists():
                raise FileExistsError(
                    "A file or folder with that name already exists"
                )

            path.rename(new_path)
            new_key = self._relative(new_path)

            new_folders = {}
            for old_path, metadata_value in self.metadata["folders"].items():
                if old_path == old_key:
                    new_folders[new_key] = metadata_value
                elif old_path.startswith(old_key + "/"):
                    new_folders[new_key + old_path[len(old_key):]] = metadata_value
                else:
                    new_folders[old_path] = metadata_value

            new_files = {}
            for old_path, metadata_value in self.metadata["files"].items():
                if old_path.startswith(old_key + "/"):
                    new_files[new_key + old_path[len(old_key):]] = metadata_value
                else:
                    new_files[old_path] = metadata_value

            self.metadata["folders"] = new_folders
            self.metadata["files"] = new_files
            self._save_metadata()
            return self._result(
                "rename_folder", new_key, metadata,
                old_path=old_key, new_path=new_key
            )

    def delete_folder(self, relative_path, delete_key):
        with self.lock:
            path = self._clean_path(relative_path)
            key = self._relative(path)
            metadata = self.metadata["folders"].get(key)
            if metadata is None or not path.is_dir():
                raise FileNotFoundError("Folder does not exist")
            if not self._check_key(metadata, "delete_key", delete_key):
                raise PermissionError("Invalid folder delete key")

            shutil.rmtree(path)
            self.metadata["folders"] = {
                k: v for k, v in self.metadata["folders"].items()
                if k != key and not k.startswith(key + "/")
            }
            self.metadata["files"] = {
                k: v for k, v in self.metadata["files"].items()
                if not k.startswith(key + "/")
            }
            self._save_metadata()
            return self._result("delete_folder", key, metadata)

    def _make_handler(self):
        store = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "PythonFileStore/1.0"

            def log_message(self, fmt, *args):
                print(f"[{self.address_string()}] {fmt % args}")

            def query(self):
                return parse_qs(urlparse(self.path).query)

            def get_one(self, name, default=None):
                return self.query().get(name, [default])[0]

            def send_json(self, data, status=200):
                body = json.dumps(data, indent=2).encode("utf-8")
                self.send_response(status)
                self.send_header(
                    "Content-Type", "application/json; charset=utf-8"
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def error(self, status, message):
                self.send_json(
                    {"success": False, "error": message}, status
                )

            def authenticate_upload(self):
                if store.api_token is None:
                    return True

                token = (
                    self.headers.get("Authorization")
                    or self.get_one("api_token")
                )
                if token and token.startswith("Bearer "):
                    token = token[7:]

                if (
                    not token
                    or not secrets.compare_digest(token, store.api_token)
                ):
                    self.error(401, "Valid API token required for upload")
                    return False
                return True

            def read_body(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError as exc:
                    raise ValueError("Invalid Content-Length") from exc

                if length < 0:
                    raise ValueError("Invalid Content-Length")

                return self.rfile.read(length)

            def show_ui(self):
                body = b"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FileStore</title>
<style>
body { font-family: system-ui,sans-serif; max-width:1000px;
       margin:40px auto; padding:0 20px; }
input,button { padding:8px; margin:4px; }
pre { white-space:pre-wrap; word-break:break-word;
      background:#f5f5f5; padding:12px; border-radius:8px; }
</style>
</head>
<body>
<h1>FileStore</h1>

<h2>Upload</h2>
<form id="upload">
<input type="file" id="file" required>
<input id="path" placeholder="path/file" required>
<button>Upload</button>
</form>

<h2>Create folder</h2>
<form id="folder">
<input id="folderPath" placeholder="folder/path" required>
<button>Create folder</button>
</form>

<h2>Result</h2>
<pre id="result">No operation yet.</pre>

<script>
async function output(response) {
    const text = await response.text();
    try {
        result.textContent = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
        result.textContent = text;
    }
}

upload.onsubmit = async (event) => {
    event.preventDefault();
    const file = document.getElementById("file").files[0];
    const path = document.getElementById("path").value;
    await output(fetch(
        "/api/upload?path=" + encodeURIComponent(path),
        {method:"POST", body:await file.arrayBuffer()}
    ));
};

folder.onsubmit = async (event) => {
    event.preventDefault();
    const path = document.getElementById("folderPath").value;
    await output(fetch(
        "/api/folder?path=" + encodeURIComponent(path),
        {method:"POST"}
    ));
};
</script>
</body>
</html>
"""
                self.send_response(200)
                self.send_header(
                    "Content-Type", "text/html; charset=utf-8"
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                try:
                    path = urlparse(self.path).path

                    if path == "/":
                        return self.show_ui()

                    if path.startswith("/file/"):
                        relative = unquote(path[len("/file/"):])
                        data, metadata = store.read_file(
                            relative, self.get_one("read_key")
                        )

                        self.send_response(200)
                        self.send_header(
                            "Content-Type", "application/octet-stream"
                        )
                        self.send_header(
                            "Content-Length", str(len(data))
                        )

                        # Every file operation outputs every file key.
                        for name, value in metadata.items():
                            self.send_header(
                                "X-" + name.replace("_", "-").title(),
                                value,
                            )

                        self.end_headers()
                        self.wfile.write(data)
                        return

                    if path == "/api/list":
                        with store.lock:
                            return self.send_json({
                                "success": True,
                                "files": store.metadata["files"],
                                "folders": store.metadata["folders"],
                            })

                    self.error(404, "Not found")

                except PermissionError as exc:
                    self.error(403, str(exc))
                except FileNotFoundError as exc:
                    self.error(404, str(exc))
                except Exception as exc:
                    self.error(500, str(exc))

            def do_POST(self):
                try:
                    path = urlparse(self.path).path

                    if path == "/api/upload":
                        if not self.authenticate_upload():
                            return
                        result = store.upload_file(
                            self.get_one("path"), self.read_body()
                        )

                    elif path == "/api/folder":
                        result = store.create_folder(
                            self.get_one("path")
                        )

                    elif path == "/api/edit":
                        result = store.edit_file(
                            self.get_one("path"),
                            self.get_one("edit_key"),
                            self.read_body(),
                        )

                    elif path == "/api/delete":
                        result = store.delete_file(
                            self.get_one("path"),
                            self.get_one("delete_key"),
                        )

                    elif path == "/api/rename":
                        result = store.rename_file(
                            self.get_one("path"),
                            self.get_one("rename_key"),
                            self.get_one("new_name"),
                        )

                    elif path == "/api/folder/edit":
                        result = store.edit_folder(
                            self.get_one("path"),
                            self.get_one("edit_key"),
                        )

                    elif path == "/api/folder/delete":
                        result = store.delete_folder(
                            self.get_one("path"),
                            self.get_one("delete_key"),
                        )

                    elif path == "/api/folder/rename":
                        result = store.rename_folder(
                            self.get_one("path"),
                            self.get_one("rename_key"),
                            self.get_one("new_name"),
                        )

                    else:
                        return self.error(404, "Not found")

                    self.send_json(result)

                except PermissionError as exc:
                    self.error(403, str(exc))
                except FileNotFoundError as exc:
                    self.error(404, str(exc))
                except FileExistsError as exc:
                    self.error(409, str(exc))
                except (ValueError, TypeError) as exc:
                    self.error(400, str(exc))
                except Exception as exc:
                    self.error(500, str(exc))

            do_PUT = do_POST

        return Handler

    def serve_forever(self):
        print(f"FileStore listening on http://{self.host}:{self.port}/")
        print(f"Storage directory: {self.root}")
        print(
            "API-token authentication:",
            "enabled" if self.api_token else "disabled",
        )
        self.httpd.serve_forever()

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    server = Server("0.0.0.0", 8080)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
        server.shutdown()
