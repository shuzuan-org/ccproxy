#!/usr/bin/env python3
"""Mock GitHub Releases API for ccproxy upgrade integration tests.

Serves fake release metadata and assets so go-selfupdate can detect
and download a "new" version without hitting real GitHub.

Environment variables:
  MOCK_PORT        - listen port (default: 9999)
  MOCK_VERSION     - release version tag, e.g. "0.0.2-test"
  MOCK_REPO        - owner/repo, e.g. "shuzuan-org/ccproxy"
  MOCK_RELEASE_DIR - directory containing tarball + checksums.txt
"""

import http.server
import json
import os
import re
import sys

PORT = int(os.environ.get("MOCK_PORT", "9999"))
VERSION = os.environ.get("MOCK_VERSION", "0.0.2-test")
REPO = os.environ.get("MOCK_REPO", "shuzuan-org/ccproxy")
RELEASE_DIR = os.environ.get("MOCK_RELEASE_DIR", "/opt/mock-release")

OWNER, REPO_NAME = REPO.split("/", 1)

TARBALL_NAME = f"ccproxy_{VERSION}_linux_amd64.tar.gz"

# Fixed asset IDs for routing.
ASSET_TARBALL = 1
ASSET_CHECKSUMS = 2

ASSETS_MAP = {
    ASSET_TARBALL: TARBALL_NAME,
    ASSET_CHECKSUMS: "checksums.txt",
}

RELEASES_PREFIX = f"/repos/{OWNER}/{REPO_NAME}/releases"
ASSET_PATTERN = re.compile(
    rf"/repos/{re.escape(OWNER)}/{re.escape(REPO_NAME)}/releases/assets/(\d+)"
)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Strip query string for matching.
        path = self.path.split("?")[0]

        # go-github Enterprise client prepends /api/v3 to all paths.
        if path.startswith("/api/v3"):
            path = path[len("/api/v3"):]

        if path == RELEASES_PREFIX:
            return self._list_releases()

        m = ASSET_PATTERN.match(path)
        if m:
            return self._download_asset(int(m.group(1)))

        self.send_error(404, f"not found: {self.path}")

    # ---- handlers ----

    def _list_releases(self):
        assets = []
        for aid, name in ASSETS_MAP.items():
            fpath = os.path.join(RELEASE_DIR, name)
            size = os.path.getsize(fpath) if os.path.exists(fpath) else 0
            assets.append({
                "id": aid,
                "name": name,
                "state": "uploaded",
                "content_type": "application/octet-stream",
                "size": size,
                "browser_download_url": f"http://127.0.0.1:{PORT}/download/{name}",
            })

        releases = [{
            "id": 1,
            "tag_name": f"v{VERSION}",
            "name": f"v{VERSION}",
            "draft": False,
            "prerelease": False,
            "assets": assets,
        }]

        body = json.dumps(releases).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _download_asset(self, asset_id):
        name = ASSETS_MAP.get(asset_id)
        if not name:
            self.send_error(404, f"unknown asset id {asset_id}")
            return

        fpath = os.path.join(RELEASE_DIR, name)
        if not os.path.exists(fpath):
            self.send_error(404, f"file not found: {fpath}")
            return

        with open(fpath, "rb") as f:
            data = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[mock-github] {fmt % args}\n")


if __name__ == "__main__":
    srv = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Mock GitHub API on :{PORT}  version={VERSION} repo={REPO}", file=sys.stderr)
    print(f"  release_dir={RELEASE_DIR}", file=sys.stderr)
    srv.serve_forever()
