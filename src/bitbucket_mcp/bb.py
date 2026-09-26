#!/usr/bin/env python3
"""bb -- Bitbucket Cloud from the command line, and as an MCP server.

Reads its credentials from ~/.netrc (machine api.bitbucket.org), which `bb-auth`
writes. The token and the Authorization header are never printed.

Run `bb --help` for the command list, and `bb mcp-serve` to serve the two MCP
tools (bb_read, bb_write) over HTTP. Configuration comes from environment
variables; see config.example.env.
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import io
import json
import netrc
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.1"

API_BASE = "https://api.bitbucket.org/2.0"
MACHINE = "api.bitbucket.org"
# The repository used when --repo is not given, as WORKSPACE/SLUG. No default.
DEFAULT_REPO = os.environ.get("BB_DEFAULT_REPO", "").strip()
USER_AGENT = "bb/%s" % __version__
MAX_RETRY_429 = 3
DEFAULT_TIMEOUT = 60.0

# The only place the token may ever be sent. Tests override this.
ALLOWED_ORIGIN = "https://api.bitbucket.org"

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
REPO_ROOT_RE = re.compile(r"^/2\.0/repositories/([^/]+)/([^/]+)/?$")


# ==========================================================================
# errors
# ==========================================================================
class BbError(Exception):
    """A failure that should end the program with a message and an exit code."""

    def __init__(self, message, code=1):
        Exception.__init__(self, message)
        self.message = message
        self.code = code


class HttpError(BbError):
    def __init__(self, status, url, body, headers=None):
        self.status = status
        self.url = url
        self.body = body
        self.headers = headers or {}
        BbError.__init__(self, "HTTP %s %s" % (status, url), 1)


# ==========================================================================
# secrets: read them, never show them
# ==========================================================================
class Auth(object):
    def __init__(self, login, token):
        self.login = login
        self._token = token
        self._basic = base64.b64encode(
            ("%s:%s" % (login, token)).encode("utf-8")
        ).decode("ascii")

    def header(self):
        return "Basic " + self._basic

    def secrets(self):
        """Every string that must never reach stdout or stderr."""
        return (self._token, self._basic)


def load_auth(machine=MACHINE):
    """Read credentials with the stdlib netrc module. Never prints the file."""
    try:
        parsed = netrc.netrc()
    except FileNotFoundError:
        raise BbError("No ~/.netrc. Run: bb-auth", 2)
    except netrc.NetrcParseError as exc:
        raise BbError("~/.netrc could not be parsed (%s). Run: bb-auth" % exc, 2)
    found = parsed.authenticators(machine)
    if not found or not found[2]:
        raise BbError("No '%s' entry in ~/.netrc. Run: bb-auth" % machine, 2)
    return Auth(found[0] or "", found[2])


_SECRETS = []


def register_secrets(auth):
    for value in auth.secrets():
        if value and value not in _SECRETS:
            _SECRETS.append(value)


def scrub(text):
    """Remove anything secret from a string that is about to be printed."""
    if text is None:
        return text
    if not isinstance(text, str):
        text = str(text)
    for value in _SECRETS:
        if value:
            text = text.replace(value, "***")
    return text


def out(text=""):
    sys.stdout.write(scrub(text) + "\n")


def note(text):
    sys.stderr.write(scrub(text) + "\n")


# ==========================================================================
# transport (swapped out by the tests)
# ==========================================================================
class Response(object):
    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body if isinstance(body, bytes) else (body or "").encode("utf-8")
        self.url = url

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    @property
    def content_type(self):
        return self.headers.get("content-type", "")

    def json(self):
        if not self.body:
            return None
        try:
            return json.loads(self.text)
        except ValueError:
            return None


def origin_of(url):
    """(scheme, host, port) for a URL, filling in the default port, or None."""
    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return None
    try:
        port = parts.port
    except ValueError:  # a malformed port
        return None
    if port is None:
        port = {"https": 443, "http": 80}.get(parts.scheme.lower())
    return (parts.scheme.lower(), parts.hostname.lower(), port)


def is_allowed_origin(url):
    """True when this URL is the one host the token may be sent to."""
    here = origin_of(url)
    return here is not None and here == origin_of(ALLOWED_ORIGIN)


def host_of(url):
    parts = urllib.parse.urlsplit(url)
    return parts.netloc or url


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never carry the token off the allowed origin.

    Python's own handler copies every header except Content-Length and
    Content-Type onto the new request, whatever the host. Bitbucket redirects
    a finished pipeline step's log to pre-signed storage, so without this the
    token would be handed to that host. Pre-signed URLs carry their own
    credentials and work fine without ours.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl
        )
        if new is None:
            return None
        target = new.full_url
        if is_allowed_origin(target):
            return new
        if urllib.parse.urlsplit(target).scheme.lower() != "https":
            raise BbError(
                "refusing to follow a redirect to %s (not https)" % host_of(target), 2
            )
        new.remove_header("Authorization")
        return new


class HttpTransport(object):
    """The real network layer. Tests replace this object."""

    def __init__(self):
        self._opener = urllib.request.build_opener(SafeRedirectHandler())

    def send(self, method, url, headers, body, timeout):
        request = urllib.request.Request(url, data=body, method=method)
        for key, value in headers.items():
            request.add_header(key, value)
        try:
            with self._opener.open(request, timeout=timeout) as resp:
                return Response(resp.status, dict(resp.headers.items()), resp.read(), url)
        except urllib.error.HTTPError as exc:
            return Response(exc.code, dict(exc.headers.items()), exc.read(), url)
        except urllib.error.URLError as exc:
            raise BbError("Could not reach %s: %s" % (url, exc.reason), 1)


# ==========================================================================
# client
# ==========================================================================
class Client(object):
    def __init__(
        self,
        auth,
        repo=DEFAULT_REPO,
        transport=None,
        dry_run=False,
        timeout=DEFAULT_TIMEOUT,
        confirm_delete_repository=None,
        sleep=time.sleep,
    ):
        self.auth = auth
        self.repo = repo
        self.transport = transport or HttpTransport()
        self.dry_run = dry_run
        self.timeout = timeout
        self.confirm_delete_repository = confirm_delete_repository
        self.sleep = sleep

    # ---- urls ----------------------------------------------------------
    @staticmethod
    def segment(value):
        """Percent-encode one path segment (slashes and braces included)."""
        return urllib.parse.quote(str(value), safe="")

    @staticmethod
    def spec(value):
        """Encode a revision spec, keeping the separators Bitbucket needs."""
        return urllib.parse.quote(str(value), safe=".:~^%")

    def repo_path(self, tail=""):
        if not self.repo:
            raise BbError(
                "No repository. Pass --repo WORKSPACE/SLUG, or set BB_DEFAULT_REPO.", 2
            )
        workspace, _, slug = self.repo.partition("/")
        if not workspace or not slug:
            raise BbError(
                "--repo must look like WORKSPACE/SLUG (got %r)" % self.repo, 2
            )
        path = "/repositories/%s/%s" % (self.segment(workspace), self.segment(slug))
        if tail:
            path += "/" + tail.lstrip("/")
        return path

    def build_url(self, path, query=None):
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = API_BASE + "/" + path.lstrip("/")
        if query:
            pairs = []
            for key, value in query:
                if value is None:
                    continue
                pairs.append((key, str(value)))
            if pairs:
                joiner = "&" if "?" in url else "?"
                url += joiner + urllib.parse.urlencode(pairs)
        return url

    # ---- guards --------------------------------------------------------
    def _guard_repository_delete(self, method, url):
        if method != "DELETE":
            return
        parts = urllib.parse.urlsplit(url)
        match = REPO_ROOT_RE.match(parts.path)
        if not match:
            return
        target = "%s/%s" % (
            urllib.parse.unquote(match.group(1)),
            urllib.parse.unquote(match.group(2)),
        )
        if self.confirm_delete_repository != target:
            raise BbError(
                "Refusing to delete the whole repository %s.\n"
                "If that is really what you want, repeat the name:\n"
                "    --confirm-delete-repository %s" % (target, target),
                2,
            )

    # ---- requests ------------------------------------------------------
    def request(self, method, path, query=None, body=None, raw=False):
        """Send one request. Returns a Response, or None for a dry run."""
        method = method.upper()
        url = self.build_url(path, query)
        if not is_allowed_origin(url):
            raise BbError("refusing to send credentials to %s" % host_of(url), 2)
        self._guard_repository_delete(method, url)

        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")

        if method not in SAFE_METHODS and self.dry_run:
            out("DRY RUN -- nothing was sent")
            out("%s %s" % (method, url))
            if body is not None:
                out(json.dumps(body, indent=2))
            return None

        headers = {
            "Authorization": self.auth.header(),
            "User-Agent": USER_AGENT,
            "Accept": "*/*" if raw else "application/json",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"

        attempt = 0
        while True:
            resp = self.transport.send(method, url, headers, payload, self.timeout)
            if resp.status == 429 and attempt < MAX_RETRY_429:
                attempt += 1
                delay = self._retry_after(resp, attempt)
                note(
                    "Rate limited (429). Waiting %ss, then retry %s of %s."
                    % (delay, attempt, MAX_RETRY_429)
                )
                self.sleep(delay)
                continue
            if resp.status >= 400:
                raise HttpError(resp.status, url, resp.text, resp.headers)
            return resp

    @staticmethod
    def _retry_after(resp, attempt):
        value = resp.headers.get("retry-after")
        try:
            delay = float(value)
        except (TypeError, ValueError):
            delay = 0.0
        if delay <= 0:
            delay = float(2 ** attempt)
        return min(delay, 120.0)

    def get_json(self, path, query=None):
        resp = self.request("GET", path, query=query)
        return resp.json() if resp else None

    def paginate(self, path, query=None, fetch_all=False, limit=None):
        """Return (payload, items, pages_left).

        pages_left is an int when Bitbucket reports a size, -1 when there is a
        next page of unknown count, and 0 when this is the last page.
        """
        first = self.get_json(path, query=query) or {}
        items = list(first.get("values") or [])
        pages_left = self._pages_left(first)
        if not fetch_all:
            return first, items, pages_left

        seen_pages = 1
        nxt = first.get("next")
        while nxt:
            if limit is not None and len(items) >= limit:
                break
            page = self.get_json(nxt) or {}
            items.extend(page.get("values") or [])
            nxt = page.get("next")
            seen_pages += 1
        merged = dict(first)
        merged["values"] = items
        merged.pop("next", None)
        merged.pop("previous", None)
        merged.pop("page", None)
        merged["size"] = first.get("size", len(items))
        merged["pagelen"] = len(items)
        return merged, items, 0

    @staticmethod
    def _pages_left(payload):
        if not payload.get("next"):
            return 0
        size = payload.get("size")
        pagelen = payload.get("pagelen")
        page = payload.get("page") or 1
        if isinstance(size, int) and isinstance(pagelen, int) and pagelen > 0:
            total = (size + pagelen - 1) // pagelen
            return max(total - int(page), 0)
        return -1


# ==========================================================================
# error reporting
# ==========================================================================
SCOPE_RE = re.compile(r"\b[a-z_]+:[a-z_]+(?::[a-z_]+)?\b")


def describe_error(exc):
    """Turn an HttpError into lines for stderr. Never shows credentials."""
    lines = ["HTTP %s  %s" % (exc.status, exc.url)]
    body = exc.body or ""
    payload = None
    try:
        payload = json.loads(body)
    except ValueError:
        payload = None

    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            if err.get("message"):
                lines.append(str(err["message"]))
            detail = err.get("detail")
            if isinstance(detail, dict):
                lines.append(json.dumps(detail, indent=2))
            elif detail:
                lines.append(str(detail))
            fields = err.get("fields")
            if fields:
                lines.append(json.dumps(fields, indent=2))
        elif payload.get("error_description"):
            lines.append(str(payload["error_description"]))
        else:
            lines.append(json.dumps(payload, indent=2))
    elif body.strip():
        lines.append(body.strip()[:2000])

    if exc.status == 403:
        lines.extend(scope_hint(exc, payload, body))
    if exc.status == 401:
        lines.append(
            "401 means the token was rejected. Create a new one and run: bb-auth"
        )
    if exc.status == 555:
        lines.append(
            "555 is Bitbucket's 'this took too long'. Diffs are not paginated, so "
            "narrow the request (--path) or try again."
        )
    if exc.status == 409:
        lines.append(
            "409 usually means the branches moved while the merge was running. "
            "Re-read the pull request and try again."
        )
    return lines


def parse_scopes(headers):
    """The scopes Bitbucket says this token holds (it sends them on every reply)."""
    raw = (headers or {}).get("x-oauth-scopes") or ""
    return [s.strip() for s in raw.split(",") if s.strip()]


def scope_hint(exc, payload, body):
    """Name the scopes Bitbucket says are missing, if it says anything."""
    required, granted = [], []
    if isinstance(payload, dict):
        detail = (payload.get("error") or {}).get("detail")
        if isinstance(detail, dict):
            required = list(detail.get("required") or [])
            granted = list(detail.get("granted") or [])

    header = exc.headers.get("www-authenticate", "")
    if not required and header:
        match = re.search(r'scope="([^"]+)"', header)
        if match:
            required = match.group(1).split()

    held = granted or parse_scopes(exc.headers)

    if not required:
        blob = " ".join(
            filter(None, [body if isinstance(body, str) else "", header])
        )
        candidates = [
            s
            for s in SCOPE_RE.findall(blob)
            if s.endswith(":bitbucket")
            or s.split(":")[0] in ("repository", "pullrequest", "pipeline", "account",
                                   "webhook", "issue", "wiki", "project", "team",
                                   "snippet", "email")
        ]
        required = sorted(set(candidates))

    lines = []
    if required:
        missing = [s for s in required if s not in held] or required
        lines.append("Missing scope(s) named by Bitbucket: " + ", ".join(missing))
        if held:
            lines.append("Scopes the token does have: " + ", ".join(sorted(held)))
        lines.append("Fix: create a new API token with those scopes, then run: bb-auth")
    elif held:
        # Bitbucket reports the token's scopes on every reply, so when it names
        # no missing scope we can say which of the two causes this is.
        admin = sorted(s for s in held if s.startswith(("admin:", "write:", "delete:")))
        lines.append(
            "Bitbucket named no missing scope, and the token already holds %s "
            "scope(s)%s."
            % (len(held), (" including " + ", ".join(admin[:4])) if admin else "")
        )
        lines.append(
            "So this is a Bitbucket account permission, not the token: you do not "
            "have the access level this endpoint needs (usually repository or "
            "workspace admin). A new token will not help; ask a workspace admin."
        )
    else:
        lines.append(
            "403 with no scope named in the reply. Two usual causes: the token "
            "lacks a scope, or your Bitbucket account lacks the permission "
            "(for example repository admin). The message above says which."
        )
    return lines


# ==========================================================================
# output
# ==========================================================================
def print_json(payload):
    out(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False))


def first_line(text, width=100):
    if not text:
        return ""
    line = str(text).strip().splitlines()[0] if str(text).strip() else ""
    return line[:width]


def short_hash(value):
    return (value or "")[:12]


def short_date(value):
    return (value or "")[:19].replace("T", " ")


def brief_line(item):
    """One short line for one object. Falls back to something sensible."""
    if not isinstance(item, dict):
        return str(item)
    kind = item.get("type") or ""

    if kind == "user" or ("account_id" in item and "display_name" in item and not kind):
        return "  ".join(
            filter(
                None,
                [
                    item.get("account_id", ""),
                    item.get("display_name", ""),
                    "(%s)" % item["nickname"] if item.get("nickname") else "",
                ],
            )
        )
    if kind == "repository":
        branch = (item.get("mainbranch") or {}).get("name", "")
        return "  ".join(
            filter(
                None,
                [
                    item.get("full_name", ""),
                    "[%s]" % branch if branch else "",
                    "private" if item.get("is_private") else "public",
                    first_line(item.get("description"), 60),
                ],
            )
        )
    if kind in ("branch", "tag", "named_branch", "bookmark"):
        target = item.get("target") or {}
        return "  ".join(
            filter(
                None,
                [
                    item.get("name", ""),
                    short_hash(target.get("hash")),
                    short_date(target.get("date")),
                    first_line(target.get("message"), 60),
                ],
            )
        )
    if kind == "commit":
        author = (item.get("author") or {})
        who = (author.get("user") or {}).get("display_name") or first_line(
            author.get("raw"), 40
        )
        return "  ".join(
            filter(
                None,
                [
                    short_hash(item.get("hash")),
                    short_date(item.get("date")),
                    who,
                    first_line(item.get("message"), 70),
                ],
            )
        )
    if kind == "pullrequest":
        source = ((item.get("source") or {}).get("branch") or {}).get("name", "?")
        dest = ((item.get("destination") or {}).get("branch") or {}).get("name", "?")
        return "  ".join(
            filter(
                None,
                [
                    "#%s" % item.get("id"),
                    item.get("state", ""),
                    "%s -> %s" % (source, dest),
                    (item.get("author") or {}).get("display_name", ""),
                    first_line(item.get("title"), 70),
                ],
            )
        )
    if kind in ("pullrequest_comment", "issue_comment"):
        inline = item.get("inline") or {}
        where = ""
        if inline.get("path"):
            where = "%s:%s" % (inline["path"], inline.get("to") or inline.get("from") or "")
        flag = "(deleted)" if item.get("deleted") else ""
        return "  ".join(
            filter(
                None,
                [
                    str(item.get("id", "")),
                    (item.get("user") or {}).get("display_name", ""),
                    short_date(item.get("created_on")),
                    where,
                    flag,
                    first_line((item.get("content") or {}).get("raw"), 70),
                ],
            )
        )
    if "task" in kind or ("state" in item and "content" in item and "id" in item
                          and isinstance(item.get("content"), dict)
                          and "creator" in item):
        return "  ".join(
            filter(
                None,
                [
                    str(item.get("id", "")),
                    str(item.get("state", "")),
                    first_line((item.get("content") or {}).get("raw"), 80),
                ],
            )
        )
    if kind == "pipeline":
        state = item.get("state") or {}
        result = (state.get("result") or state.get("stage") or {}).get("name", "")
        target = item.get("target") or {}
        return "  ".join(
            filter(
                None,
                [
                    "#%s" % item.get("build_number", ""),
                    str(item.get("uuid", "")),
                    "%s/%s" % (state.get("name", "?"), result or "-"),
                    target.get("ref_name", "") or "",
                    short_date(item.get("created_on")),
                ],
            )
        )
    if kind == "pipeline_step":
        state = item.get("state") or {}
        result = (state.get("result") or {}).get("name", "")
        return "  ".join(
            filter(
                None,
                [
                    str(item.get("uuid", "")),
                    item.get("name", "") or "(unnamed step)",
                    "%s/%s" % (state.get("name", "?"), result or "-"),
                ],
            )
        )
    if kind == "diffstat":
        new = item.get("new") or {}
        old = item.get("old") or {}
        path = new.get("path") or old.get("path") or ""
        return "  ".join(
            filter(
                None,
                [
                    item.get("status", ""),
                    "+%s -%s" % (item.get("lines_added", 0), item.get("lines_removed", 0)),
                    path,
                ],
            )
        )
    if kind == "build":
        return "  ".join(
            filter(
                None,
                [
                    item.get("key", ""),
                    item.get("state", ""),
                    first_line(item.get("name"), 50),
                    item.get("url", ""),
                ],
            )
        )
    if kind == "branchrestriction":
        return "  ".join(
            filter(
                None,
                [
                    str(item.get("id", "")),
                    item.get("kind", ""),
                    item.get("pattern", "") or "(branch type: %s)" % item.get("branch_match_kind", ""),
                ],
            )
        )
    if kind in ("commit_file", "commit_directory"):
        mark = "dir " if kind == "commit_directory" else "file"
        size = item.get("size")
        return "  ".join(
            filter(
                None,
                [
                    mark,
                    "%8s" % size if isinstance(size, int) else "",
                    item.get("path", ""),
                ],
            )
        )
    if not kind and "pull_request" in item:
        # A pull request activity entry: exactly one of these keys is filled in.
        for key, label in (
            ("update", "update"),
            ("approval", "approved"),
            ("changes_requested", "changes requested"),
            ("comment", "comment"),
        ):
            entry = item.get(key)
            if not isinstance(entry, dict):
                continue
            who = (entry.get("user") or entry.get("author") or {}).get("display_name", "")
            when = short_date(
                entry.get("date") or entry.get("created_on") or entry.get("updated_on")
            )
            extra = ""
            if key == "update":
                extra = entry.get("state", "") or ""
                if entry.get("title"):
                    extra = (extra + " " + first_line(entry["title"], 50)).strip()
            elif key == "comment":
                extra = first_line((entry.get("content") or {}).get("raw"), 60)
            return "  ".join(filter(None, [when, label, who, extra]))
        return "  ".join(
            filter(None, ["#%s" % (item.get("pull_request") or {}).get("id", "?"), "(activity)"])
        )
    if kind == "default_reviewer" or ("user" in item and isinstance(item.get("user"), dict)):
        return brief_line(item["user"])

    for key in ("full_name", "name", "title", "display_name", "uuid", "id", "hash", "key"):
        if item.get(key):
            return "%s: %s" % (key, item[key])
    return json.dumps(item)[:160]


def emit(payload, brief=False, items=None):
    """Print a Bitbucket payload, as JSON or as brief lines."""
    if payload is None:
        return
    if not brief:
        print_json(payload)
        return
    if items is None:
        items = payload.get("values") if isinstance(payload, dict) else None
    if items is None:
        out(brief_line(payload))
        return
    if not items:
        note("(no results)")
        return
    for item in items:
        out(brief_line(item))


def emit_text(resp):
    """Print a plain-text body (a diff, a file, a log)."""
    if resp is None:
        return
    if "application/json" in resp.content_type:
        payload = resp.json()
        if payload is not None:
            print_json(payload)
            return
    sys.stdout.write(scrub(resp.text))
    if resp.text and not resp.text.endswith("\n"):
        sys.stdout.write("\n")


def report_pages(pages_left, fetch_all, count):
    if fetch_all:
        note("Fetched %s items (all pages)." % count)
        return
    if pages_left == 0:
        return
    if pages_left < 0:
        note("Showing the first page. More pages remain; use --all to fetch them.")
    else:
        note(
            "Showing the first page. %s more page(s) remain; use --all to fetch them."
            % pages_left
        )


# ==========================================================================
# small helpers
# ==========================================================================
def read_text_arg(path, what="text"):
    """Read body text from a file, or from stdin when the path is '-'."""
    if path == "-":
        data = sys.stdin.read()
    else:
        try:
            with io.open(path, "r", encoding="utf-8") as fh:
                data = fh.read()
        except OSError as exc:
            raise BbError("Could not read the %s file %s: %s" % (what, path, exc), 2)
    return data


def text_arg(inline, path, what="text"):
    """Text given inline, or read from a file, or nothing at all."""
    if inline is not None:
        return inline
    if path:
        return read_text_arg(path, what)
    return None


def user_ref(user):
    """The identifier Bitbucket accepts in a reviewers list."""
    if not isinstance(user, dict):
        return None
    if user.get("account_id"):
        return {"account_id": user["account_id"]}
    if user.get("uuid"):
        return {"uuid": user["uuid"]}
    return None


def user_id(user):
    if not isinstance(user, dict):
        return None
    return user.get("account_id") or user.get("uuid")


# ==========================================================================
# commands
# ==========================================================================
def cmd_whoami(client, args):
    payload = client.get_json("/user")
    emit(payload, args.brief)


def cmd_scopes(client, args):
    """Show the scopes Bitbucket says this token holds. Never shows the token."""
    resp = client.request("GET", "/user")
    if resp is None:
        return
    held = parse_scopes(resp.headers)
    if not held:
        note(
            "Bitbucket did not report any scopes for this credential "
            "(header X-Oauth-Scopes was absent)."
        )
        return
    if args.brief:
        out(", ".join(sorted(held)))
        return
    print_json(
        {
            "credential_type": resp.headers.get("x-credential-type", "unknown"),
            "count": len(held),
            "scopes": sorted(held),
        }
    )


def cmd_repo_get(client, args):
    payload = client.get_json(client.repo_path())
    emit(payload, args.brief)


def cmd_repo_list(client, args):
    workspace = args.workspace or (client.repo or "").split("/")[0]
    if not workspace:
        raise BbError("Name a workspace: bb repo list WORKSPACE", 2)
    payload, items, left = client.paginate(
        "/repositories/%s" % Client.segment(workspace),
        query=[("sort", "-updated_on")],
        fetch_all=args.fetch_all,
    )
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


def cmd_branch_list(client, args):
    query = [("sort", "-target.date")]
    if args.name:
        query.append(("q", 'name ~ "%s"' % args.name.replace('"', '\\"')))
    payload, items, left = client.paginate(
        client.repo_path("refs/branches"), query=query, fetch_all=args.fetch_all
    )
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


def cmd_branch_get(client, args):
    payload = client.get_json(
        client.repo_path("refs/branches/%s" % Client.segment(args.name))
    )
    emit(payload, args.brief)


def cmd_branch_create(client, args):
    body = {"name": args.name, "target": {"hash": args.source}}
    resp = client.request("POST", client.repo_path("refs/branches"), body=body)
    if resp:
        emit(resp.json(), args.brief)


def cmd_branch_delete(client, args):
    resp = client.request(
        "DELETE", client.repo_path("refs/branches/%s" % Client.segment(args.name))
    )
    if resp:
        note("Deleted branch %s (HTTP %s)." % (args.name, resp.status))


def cmd_tag_list(client, args):
    query = [("sort", "-target.date")]
    if args.name:
        query.append(("q", 'name ~ "%s"' % args.name.replace('"', '\\"')))
    payload, items, left = client.paginate(
        client.repo_path("refs/tags"), query=query, fetch_all=args.fetch_all
    )
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


def cmd_tag_get(client, args):
    payload = client.get_json(
        client.repo_path("refs/tags/%s" % Client.segment(args.name))
    )
    emit(payload, args.brief)


def cmd_tag_create(client, args):
    body = {"name": args.name, "target": {"hash": args.source}}
    if args.message:
        body["message"] = args.message
    resp = client.request("POST", client.repo_path("refs/tags"), body=body)
    if resp:
        emit(resp.json(), args.brief)


def cmd_tag_delete(client, args):
    resp = client.request(
        "DELETE", client.repo_path("refs/tags/%s" % Client.segment(args.name))
    )
    if resp:
        note("Deleted tag %s (HTTP %s)." % (args.name, resp.status))


def cmd_commit_get(client, args):
    payload = client.get_json(
        client.repo_path("commit/%s" % Client.segment(args.hash))
    )
    emit(payload, args.brief)


def cmd_commit_list(client, args):
    tail = "commits"
    if args.revision:
        tail += "/" + Client.spec(args.revision)
    query = []
    if args.path:
        query.append(("path", args.path))
    payload, items, left = client.paginate(
        client.repo_path(tail), query=query or None, fetch_all=args.fetch_all
    )
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


def _diff_query(args):
    query = []
    for value in args.path or []:
        query.append(("path", value))
    if getattr(args, "context", None) is not None:
        query.append(("context", args.context))
    if getattr(args, "two_dot", False):
        query.append(("topic", "false"))
    if getattr(args, "ignore_whitespace", False):
        query.append(("ignore_whitespace", "true"))
    return query


def cmd_diff(client, args):
    resp = client.request(
        "GET",
        client.repo_path("diff/%s" % Client.spec(args.spec)),
        query=_diff_query(args) or None,
        raw=True,
    )
    emit_text(resp)


def cmd_diffstat(client, args):
    payload, items, left = client.paginate(
        client.repo_path("diffstat/%s" % Client.spec(args.spec)),
        query=_diff_query(args) or None,
        fetch_all=args.fetch_all,
    )
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


def resolve_src_ref(client, ref):
    """src/{commit}/{path} cannot route a ref name containing '/'.

    Bitbucket decodes the path before routing, so neither a raw slash nor %2F
    works there. Look the branch up and use its commit hash instead.
    """
    if "/" not in ref:
        return ref
    branch = client.get_json(
        client.repo_path("refs/branches/%s" % Client.segment(ref))
    ) or {}
    target = (branch.get("target") or {}).get("hash")
    if not target:
        raise BbError(
            "Could not resolve the branch %r to a commit. Bitbucket cannot read "
            "a file at a ref whose name contains '/', so pass a commit hash." % ref,
            2,
        )
    note("Reading at %s (%s)." % (ref, target[:12]))
    return target


def cmd_file_get(client, args):
    ref = resolve_src_ref(client, args.ref)
    path = "/".join(Client.segment(part) for part in args.path.split("/") if part != "")
    resp = client.request(
        "GET", client.repo_path("src/%s/%s" % (Client.spec(ref), path)), raw=True
    )
    emit_text(resp)


def cmd_file_list(client, args):
    ref = resolve_src_ref(client, args.ref)
    path = "/".join(
        Client.segment(part) for part in (args.path or "").split("/") if part != ""
    )
    tail = "src/%s/%s" % (Client.spec(ref), path) if path else "src/%s/" % Client.spec(ref)
    payload, items, left = client.paginate(client.repo_path(tail), fetch_all=args.fetch_all)
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


# ---- pull requests -------------------------------------------------------
def bbql_string(value):
    """Quote a value for a Bitbucket query expression."""
    return '"%s"' % str(value).replace("\\", "\\\\").replace('"', '\\"')


def looks_like_account_id(value):
    return ":" in value or bool(re.match(r"^[0-9a-f]{20,}$", value))


def cmd_pr_list(client, args):
    states = [s.upper() for s in (args.state or [])]
    filters = []

    if args.author:
        value = args.author
        is_account_id = False
        if value in ("me", "@me"):
            me = client.get_json("/user") or {}
            value = user_id(me) or ""
            if not value:
                raise BbError("Could not work out who you are; pass an account id.", 1)
            is_account_id = True
        if is_account_id or looks_like_account_id(value):
            filters.append("author.account_id = %s" % bbql_string(value))
        else:
            # Bitbucket rejects '~' on nickname expressions: "nickname
            # expressions only support '=' and '!='". So this is an exact match.
            filters.append("author.nickname = %s" % bbql_string(value))
    if args.source:
        filters.append("source.branch.name = %s" % bbql_string(args.source))
    if args.dest:
        filters.append("destination.branch.name = %s" % bbql_string(args.dest))
    if args.title:
        filters.append("title ~ %s" % bbql_string(args.title))
    if args.query:
        filters.append(args.query)

    query = []
    if filters:
        # Bitbucket ignores or mangles the separate state= parameter when a q
        # expression is also present, so fold the states into the expression.
        if states:
            if len(states) == 1:
                filters.insert(0, "state = %s" % bbql_string(states[0]))
            else:
                filters.insert(
                    0, "state IN (%s)" % ", ".join(bbql_string(s) for s in states)
                )
        query.append(("q", " AND ".join(filters)))
    else:
        for state in states:
            query.append(("state", state))
    query.append(("sort", "-updated_on"))

    payload, items, left = client.paginate(
        client.repo_path("pullrequests"), query=query, fetch_all=args.fetch_all
    )
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


def _pr_path(client, pr_id, tail=""):
    path = client.repo_path("pullrequests/%s" % Client.segment(pr_id))
    if tail:
        path += "/" + tail.lstrip("/")
    return path


def cmd_pr_get(client, args):
    emit(client.get_json(_pr_path(client, args.id)), args.brief)


def cmd_pr_sub_json(tail):
    def run(client, args):
        payload, items, left = client.paginate(
            _pr_path(client, args.id, tail), fetch_all=args.fetch_all
        )
        emit(payload, args.brief, items)
        report_pages(left, args.fetch_all, len(items))

    return run


def cmd_pr_diff(client, args):
    resp = client.request("GET", _pr_path(client, args.id, "diff"), raw=True)
    emit_text(resp)


def cmd_pr_create(client, args):
    description = text_arg(args.description, args.description_file, "description") or ""
    body = {
        "title": args.title,
        "source": {"branch": {"name": args.source}},
        "destination": {"branch": {"name": args.dest}},
        "close_source_branch": bool(args.close_source_branch),
    }
    if description:
        body["description"] = description
    if args.draft:
        body["draft"] = True

    reviewers = []
    seen = set()
    if not args.no_default_reviewers:
        me = client.get_json("/user") or {}
        mine = user_id(me)
        _payload, defaults, _left = client.paginate(
            client.repo_path("effective-default-reviewers"), fetch_all=True
        )
        for entry in defaults:
            user = entry.get("user") if isinstance(entry, dict) and "user" in entry else entry
            ident = user_id(user)
            if not ident or ident == mine or ident in seen:
                continue
            ref = user_ref(user)
            if ref:
                seen.add(ident)
                reviewers.append(ref)
    for ident in args.reviewer or []:
        if ident in seen:
            continue
        seen.add(ident)
        reviewers.append(
            {"uuid": ident} if ident.startswith("{") else {"account_id": ident}
        )
    if reviewers:
        body["reviewers"] = reviewers

    resp = client.request("POST", client.repo_path("pullrequests"), body=body)
    if resp:
        payload = resp.json() or {}
        emit(payload, args.brief)
        link = ((payload.get("links") or {}).get("html") or {}).get("href")
        if link:
            note(link)


def cmd_pr_update(client, args):
    current = client.get_json(_pr_path(client, args.id)) or {}
    state = current.get("state")
    if state != "OPEN":
        raise BbError(
            "PR #%s is %s, not OPEN. Bitbucket only accepts edits to an open PR."
            % (args.id, state or "unknown"),
            2,
        )

    reviewers = []
    seen = set()
    for user in current.get("reviewers") or []:
        ident = user_id(user)
        ref = user_ref(user)
        if ident and ref and ident not in seen:
            seen.add(ident)
            reviewers.append(ref)
    for ident in args.remove_reviewer or []:
        reviewers = [
            r for r in reviewers if r.get("account_id") != ident and r.get("uuid") != ident
        ]
        seen.discard(ident)
    for ident in args.add_reviewer or []:
        if ident in seen:
            continue
        seen.add(ident)
        reviewers.append(
            {"uuid": ident} if ident.startswith("{") else {"account_id": ident}
        )

    dest = args.dest or ((current.get("destination") or {}).get("branch") or {}).get("name")
    description = current.get("description") or ""
    new_description = text_arg(args.description, args.description_file, "description")
    if new_description is not None:
        description = new_description

    body = {
        "title": args.title if args.title is not None else current.get("title", ""),
        "description": description,
        "reviewers": reviewers,
    }
    if dest:
        body["destination"] = {"branch": {"name": dest}}

    resp = client.request("PUT", _pr_path(client, args.id), body=body)
    if resp:
        emit(resp.json(), args.brief)


def cmd_pr_comment(client, args):
    body = {"content": {"raw": text_arg(args.text, args.text_file, "comment")}}
    if args.reply_to:
        body["parent"] = {"id": int(args.reply_to)}
    resp = client.request("POST", _pr_path(client, args.id, "comments"), body=body)
    if resp:
        emit(resp.json(), args.brief)


def cmd_pr_comment_edit(client, args):
    body = {"content": {"raw": text_arg(args.text, args.text_file, "comment")}}
    resp = client.request(
        "PUT",
        _pr_path(client, args.id, "comments/%s" % Client.segment(args.comment_id)),
        body=body,
    )
    if resp:
        emit(resp.json(), args.brief)


def cmd_pr_comment_delete(client, args):
    resp = client.request(
        "DELETE",
        _pr_path(client, args.id, "comments/%s" % Client.segment(args.comment_id)),
    )
    if resp:
        note("Deleted comment %s on PR #%s (HTTP %s)." % (args.comment_id, args.id, resp.status))


def cmd_pr_task_create(client, args):
    body = {"content": {"raw": text_arg(args.text, args.text_file, "task")}}
    if args.comment:
        body["comment"] = {"id": int(args.comment)}
    resp = client.request("POST", _pr_path(client, args.id, "tasks"), body=body)
    if resp:
        emit(resp.json(), args.brief)


def cmd_pr_task_update(client, args):
    body = {}
    task_text = text_arg(args.text, args.text_file, "task")
    if task_text is not None:
        body["content"] = {"raw": task_text}
    if args.state:
        body["state"] = args.state
    if not body:
        raise BbError("Give --text-file or --text, --state, or both.", 2)
    resp = client.request(
        "PUT",
        _pr_path(client, args.id, "tasks/%s" % Client.segment(args.task_id)),
        body=body,
    )
    if resp:
        emit(resp.json(), args.brief)


def cmd_pr_task_delete(client, args):
    resp = client.request(
        "DELETE", _pr_path(client, args.id, "tasks/%s" % Client.segment(args.task_id))
    )
    if resp:
        note("Deleted task %s on PR #%s (HTTP %s)." % (args.task_id, args.id, resp.status))


def _pr_simple(method, tail, done):
    def run(client, args):
        resp = client.request(method, _pr_path(client, args.id, tail))
        if resp:
            payload = resp.json()
            if payload is not None:
                emit(payload, args.brief)
            else:
                note(done % (args.id, resp.status))

    return run


def cmd_pr_decline(client, args):
    # Bitbucket documents no request body for decline.
    resp = client.request("POST", _pr_path(client, args.id, "decline"))
    if resp:
        emit(resp.json(), args.brief)


def cmd_pr_merge(client, args):
    body = {
        "type": "pullrequest",
        "merge_strategy": args.strategy,
        "close_source_branch": bool(args.close_source_branch),
    }
    merge_message = text_arg(args.message, args.message_file, "merge message")
    if merge_message is not None:
        body["message"] = merge_message
    resp = client.request("POST", _pr_path(client, args.id, "merge"), body=body)
    if resp is None:
        return
    if resp.status == 202:
        # Bitbucket may finish the merge in the background, even for a
        # synchronous call, and hands back a link to poll.
        note("Bitbucket is finishing this merge in the background (HTTP 202).")
        location = resp.headers.get("location")
        if location:
            note("Poll it with: bb api GET %s" % location)
    emit(resp.json() or {"status": resp.status}, args.brief)


# ---- pipelines -----------------------------------------------------------
def cmd_pipeline_list(client, args):
    query = [("sort", "-created_on")]
    if args.branch:
        query.append(("target.branch", args.branch))
    payload, items, left = client.paginate(
        client.repo_path("pipelines/"), query=query, fetch_all=args.fetch_all
    )
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


def cmd_pipeline_get(client, args):
    emit(
        client.get_json(client.repo_path("pipelines/%s" % Client.segment(args.uuid))),
        args.brief,
    )


def cmd_pipeline_steps(client, args):
    payload, items, left = client.paginate(
        client.repo_path("pipelines/%s/steps/" % Client.segment(args.uuid)),
        fetch_all=args.fetch_all,
    )
    emit(payload, args.brief, items)
    report_pages(left, args.fetch_all, len(items))


def cmd_pipeline_log(client, args):
    resp = client.request(
        "GET",
        client.repo_path(
            "pipelines/%s/steps/%s/log"
            % (Client.segment(args.uuid), Client.segment(args.step_uuid))
        ),
        raw=True,
    )
    emit_text(resp)


def cmd_pipeline_run(client, args):
    target = {
        "type": "pipeline_ref_target",
        "ref_type": "branch",
        "ref_name": args.branch,
    }
    if args.pattern:
        target["selector"] = {"type": "custom", "pattern": args.pattern}
    resp = client.request("POST", client.repo_path("pipelines/"), body={"target": target})
    if resp:
        emit(resp.json(), args.brief)


def cmd_pipeline_stop(client, args):
    resp = client.request(
        "POST",
        client.repo_path("pipelines/%s/stopPipeline" % Client.segment(args.uuid)),
    )
    if resp:
        note("Stop requested for pipeline %s (HTTP %s)." % (args.uuid, resp.status))


# ---- escape hatch --------------------------------------------------------
def cmd_api(client, args):
    body = None
    if args.data and args.data_file:
        raise BbError("Give --data or --data-file, not both.", 2)
    raw_body = None
    if args.data is not None:
        raw_body = args.data
    elif args.data_file:
        raw_body = read_text_arg(args.data_file, "request body")
    if raw_body is not None and raw_body.strip():
        try:
            body = json.loads(raw_body)
        except ValueError as exc:
            raise BbError("The request body is not valid JSON: %s" % exc, 2)
    elif raw_body is not None:
        body = {}

    query = []
    for pair in args.query or []:
        key, sep, value = pair.partition("=")
        if not sep:
            raise BbError("--query needs key=value (got %r)" % pair, 2)
        query.append((key, value))

    method = args.method.upper()
    if args.paginate:
        payload, items, left = client.paginate(
            args.path, query=query or None, fetch_all=True
        )
        emit(payload, args.brief, items)
        report_pages(left, True, len(items))
        return

    resp = client.request(
        method, args.path, query=query or None, body=body, raw=args.raw
    )
    if resp is None:
        return
    if args.raw:
        emit_text(resp)
        return
    payload = resp.json()
    if payload is None:
        if resp.text.strip():
            emit_text(resp)
        else:
            note("HTTP %s (empty body)" % resp.status)
        return
    emit(payload, args.brief)


# ==========================================================================
# argument parsing
# ==========================================================================
def add_globals(parser, suppress):
    default = argparse.SUPPRESS if suppress else None
    parser.add_argument(
        "--repo",
        metavar="WORKSPACE/SLUG",
        default=argparse.SUPPRESS if suppress else DEFAULT_REPO,
        help="repository to work on (default: $BB_DEFAULT_REPO, now %s)"
        % (DEFAULT_REPO or "unset"),
    )
    parser.add_argument(
        "--brief",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="one short line per item instead of JSON",
    )
    parser.add_argument(
        "--all",
        dest="fetch_all",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="follow 'next' links and return every page",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=argparse.SUPPRESS if suppress else False,
        help="for writes: print the request and send nothing",
    )
    parser.add_argument(
        "--confirm-delete-repository",
        metavar="WORKSPACE/SLUG",
        default=argparse.SUPPRESS if suppress else None,
        help="required to delete a whole repository; must repeat its name",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        metavar="SECONDS",
        default=argparse.SUPPRESS if suppress else DEFAULT_TIMEOUT,
        help="network timeout in seconds (default: %g)" % DEFAULT_TIMEOUT,
    )
    del default


def common():
    parent = argparse.ArgumentParser(add_help=False)
    add_globals(parent, suppress=True)
    return parent


def build_parser():
    shared = common()
    parser = argparse.ArgumentParser(
        prog="bb",
        description="Bitbucket Cloud from the command line. "
        "Credentials come from ~/.netrc; run bb-auth to set them.",
        epilog="Writes accept --dry-run. Long text comes from files "
        "(--description-file, --text-file, --message-file; '-' means stdin).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_globals(parser, suppress=False)
    parser.add_argument("--version", action="version", version="bb " + __version__)
    top = parser.add_subparsers(dest="command", metavar="COMMAND")

    def leaf(subparsers, name, help_text):
        return subparsers.add_parser(name, help=help_text, parents=[shared])

    # whoami
    p = leaf(top, "whoami", "show the account the token belongs to")
    p.set_defaults(func=cmd_whoami)

    p = leaf(top, "scopes", "list the scopes this token holds (never the token)")
    p.set_defaults(func=cmd_scopes)

    # repo
    repo = top.add_parser("repo", help="repositories").add_subparsers(
        dest="subcommand", metavar="SUBCOMMAND"
    )
    p = leaf(repo, "get", "show the repository")
    p.set_defaults(func=cmd_repo_get)
    p = leaf(repo, "list", "list the repositories in a workspace")
    p.add_argument("workspace", nargs="?", help="workspace (default: the repo's own)")
    p.set_defaults(func=cmd_repo_list)

    # branch
    branch = top.add_parser("branch", help="branches").add_subparsers(
        dest="subcommand", metavar="SUBCOMMAND"
    )
    p = leaf(branch, "list", "list branches, newest commit first")
    p.add_argument("--name", metavar="TEXT", help="only branches whose name contains TEXT")
    p.set_defaults(func=cmd_branch_list)
    p = leaf(branch, "get", "show one branch")
    p.add_argument("name")
    p.set_defaults(func=cmd_branch_get)
    p = leaf(branch, "create", "create a branch (write)")
    p.add_argument("name")
    p.add_argument("--from", dest="source", required=True, metavar="BRANCH_OR_HASH")
    p.set_defaults(func=cmd_branch_create)
    p = leaf(branch, "delete", "delete a branch (write)")
    p.add_argument("name")
    p.set_defaults(func=cmd_branch_delete)

    # tag
    tag = top.add_parser("tag", help="tags").add_subparsers(
        dest="subcommand", metavar="SUBCOMMAND"
    )
    p = leaf(tag, "list", "list tags")
    p.add_argument("--name", metavar="TEXT", help="only tags whose name contains TEXT")
    p.set_defaults(func=cmd_tag_list)
    p = leaf(tag, "get", "show one tag")
    p.add_argument("name")
    p.set_defaults(func=cmd_tag_get)
    p = leaf(tag, "create", "create a tag (write)")
    p.add_argument("name")
    p.add_argument("--from", dest="source", required=True, metavar="BRANCH_OR_HASH")
    p.add_argument("--message", help="annotate the tag with this message")
    p.set_defaults(func=cmd_tag_create)
    p = leaf(tag, "delete", "delete a tag (write)")
    p.add_argument("name")
    p.set_defaults(func=cmd_tag_delete)

    # commit
    commit = top.add_parser("commit", help="commits").add_subparsers(
        dest="subcommand", metavar="SUBCOMMAND"
    )
    p = leaf(commit, "get", "show one commit")
    p.add_argument("hash")
    p.set_defaults(func=cmd_commit_get)
    p = leaf(commit, "list", "list commits on a branch, tag or hash")
    p.add_argument("revision", nargs="?", help="branch, tag or hash (default: all)")
    p.add_argument("--path", help="only commits touching this path")
    p.set_defaults(func=cmd_commit_list)

    # diff / diffstat
    diff_help = (
        "SPEC is one commit, or SOURCE..DESTINATION -- note that is the opposite "
        "order to git diff. By default Bitbucket compares against the merge base "
        "(a 'three-dot' diff); --two-dot compares the two ends directly."
    )
    p = leaf(top, "diff", "unified diff for a spec such as BRANCH..OTHER")
    p.add_argument("spec")
    p.add_argument("--path", action="append", help="limit the diff to this path; repeatable")
    p.add_argument("--context", type=int, help="lines of context")
    p.add_argument("--two-dot", action="store_true", help="compare the two ends directly")
    p.add_argument("--ignore-whitespace", action="store_true")
    p.epilog = diff_help
    p.set_defaults(func=cmd_diff)

    p = leaf(top, "diffstat", "changed files and line counts for a spec")
    p.add_argument("spec")
    p.add_argument("--path", action="append", help="limit to this path; repeatable")
    p.add_argument("--two-dot", action="store_true", help="compare the two ends directly")
    p.add_argument("--ignore-whitespace", action="store_true")
    p.epilog = diff_help
    p.set_defaults(func=cmd_diffstat)

    # file
    fil = top.add_parser("file", help="file contents").add_subparsers(
        dest="subcommand", metavar="SUBCOMMAND"
    )
    p = leaf(fil, "get", "print a file at a branch, tag or hash")
    p.add_argument("ref")
    p.add_argument("path")
    p.set_defaults(func=cmd_file_get)
    p = leaf(fil, "list", "list a directory at a branch, tag or hash")
    p.add_argument("ref")
    p.add_argument("path", nargs="?", default="")
    p.set_defaults(func=cmd_file_list)

    # pr
    pr_parser = top.add_parser("pr", help="pull requests")
    pr = pr_parser.add_subparsers(dest="subcommand", metavar="SUBCOMMAND")

    p = leaf(pr, "list", "list pull requests")
    p.add_argument(
        "--state",
        action="append",
        choices=["OPEN", "MERGED", "DECLINED", "SUPERSEDED"],
        type=str.upper,
        help="repeatable; default is OPEN",
    )
    p.add_argument(
        "--author",
        metavar="TEXT",
        help="account id, or an exact display name, or 'me' "
        "(Bitbucket has no partial match on names)",
    )
    p.add_argument("--source", metavar="BRANCH", help="source branch")
    p.add_argument("--dest", metavar="BRANCH", help="destination branch")
    p.add_argument("--title", metavar="TEXT", help="title contains TEXT")
    p.add_argument("--query", metavar="BBQL", help="extra Bitbucket query expression")
    p.set_defaults(func=cmd_pr_list)

    p = leaf(pr, "get", "show one pull request")
    p.add_argument("id")
    p.set_defaults(func=cmd_pr_get)

    p = leaf(pr, "diff", "the pull request diff")
    p.add_argument("id")
    p.set_defaults(func=cmd_pr_diff)

    for name, tail, help_text in (
        ("diffstat", "diffstat", "changed files in the pull request"),
        ("commits", "commits", "commits in the pull request"),
        ("activity", "activity", "everything that happened on the pull request"),
        ("comments", "comments", "pull request comments"),
        ("tasks", "tasks", "pull request tasks"),
        ("statuses", "statuses", "build statuses on the pull request"),
    ):
        p = leaf(pr, name, help_text)
        p.add_argument("id")
        p.set_defaults(func=cmd_pr_sub_json(tail))

    p = leaf(pr, "create", "create a pull request (write)")
    p.add_argument("--source", required=True, metavar="BRANCH")
    p.add_argument("--dest", required=True, metavar="BRANCH")
    p.add_argument("--title", required=True)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--description-file", metavar="FILE", help="'-' reads stdin")
    g.add_argument("--description", metavar="TEXT", help="the description itself")
    p.add_argument("--draft", action="store_true")
    p.add_argument(
        "--no-default-reviewers",
        action="store_true",
        help="skip the repository's default reviewers",
    )
    p.add_argument("--reviewer", action="append", metavar="ACCOUNT_ID", help="repeatable")
    p.add_argument("--close-source-branch", action="store_true")
    p.set_defaults(func=cmd_pr_create)

    p = leaf(pr, "update", "edit an open pull request (write)")
    p.add_argument("id")
    p.add_argument("--title")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--description-file", metavar="FILE", help="'-' reads stdin")
    g.add_argument("--description", metavar="TEXT", help="the description itself")
    p.add_argument("--dest", metavar="BRANCH")
    p.add_argument("--add-reviewer", action="append", metavar="ACCOUNT_ID")
    p.add_argument("--remove-reviewer", action="append", metavar="ACCOUNT_ID")
    p.set_defaults(func=cmd_pr_update)

    p = leaf(pr, "comment", "add a comment (write)")
    p.add_argument("id")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--text-file", metavar="FILE", help="'-' reads stdin")
    g.add_argument("--text", metavar="TEXT", help="the comment itself")
    p.add_argument("--reply-to", metavar="COMMENT_ID")
    p.set_defaults(func=cmd_pr_comment)

    p = leaf(pr, "comment-edit", "edit a comment (write)")
    p.add_argument("id")
    p.add_argument("comment_id", metavar="COMMENT_ID")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--text-file", metavar="FILE", help="'-' reads stdin")
    g.add_argument("--text", metavar="TEXT", help="the comment itself")
    p.set_defaults(func=cmd_pr_comment_edit)

    p = leaf(pr, "comment-delete", "delete a comment (write)")
    p.add_argument("id")
    p.add_argument("comment_id", metavar="COMMENT_ID")
    p.set_defaults(func=cmd_pr_comment_delete)

    p = leaf(pr, "task-create", "add a task (write)")
    p.add_argument("id")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--text-file", metavar="FILE", help="'-' reads stdin")
    g.add_argument("--text", metavar="TEXT", help="the task itself")
    p.add_argument("--comment", metavar="COMMENT_ID", help="attach to this comment")
    p.set_defaults(func=cmd_pr_task_create)

    p = leaf(pr, "task-update", "edit a task (write)")
    p.add_argument("id")
    p.add_argument("task_id", metavar="TASK_ID")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--text-file", metavar="FILE", help="'-' reads stdin")
    g.add_argument("--text", metavar="TEXT", help="the task itself")
    p.add_argument("--state", choices=["UNRESOLVED", "RESOLVED"])
    p.set_defaults(func=cmd_pr_task_update)

    p = leaf(pr, "task-delete", "delete a task (write)")
    p.add_argument("id")
    p.add_argument("task_id", metavar="TASK_ID")
    p.set_defaults(func=cmd_pr_task_delete)

    for name, method, tail, done in (
        ("approve", "POST", "approve", "Approved PR #%s (HTTP %s)."),
        ("unapprove", "DELETE", "approve", "Removed approval on PR #%s (HTTP %s)."),
        ("request-changes", "POST", "request-changes", "Requested changes on PR #%s (HTTP %s)."),
        (
            "remove-request-changes",
            "DELETE",
            "request-changes",
            "Removed the change request on PR #%s (HTTP %s).",
        ),
    ):
        p = leaf(pr, name, "%s (write)" % name.replace("-", " "))
        p.add_argument("id")
        p.set_defaults(func=_pr_simple(method, tail, done))

    p = leaf(pr, "decline", "decline a pull request (write)")
    p.add_argument("id")
    p.set_defaults(func=cmd_pr_decline)

    p = leaf(pr, "merge", "merge a pull request (write)")
    p.add_argument("id")
    p.add_argument(
        "--strategy",
        choices=[
            "merge_commit",
            "squash",
            "fast_forward",
            "squash_fast_forward",
            "rebase_fast_forward",
            "rebase_merge",
        ],
        default="merge_commit",
        help="default: merge_commit; the branch may not allow every strategy",
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--message-file", metavar="FILE", help="'-' reads stdin")
    g.add_argument("--message", metavar="TEXT", help="the merge message itself")
    p.add_argument("--close-source-branch", action="store_true")
    p.set_defaults(func=cmd_pr_merge)

    # pipeline
    pipe = top.add_parser("pipeline", help="pipelines").add_subparsers(
        dest="subcommand", metavar="SUBCOMMAND"
    )
    p = leaf(pipe, "list", "list pipeline runs, newest first")
    p.add_argument("--branch", metavar="BRANCH")
    p.set_defaults(func=cmd_pipeline_list)
    p = leaf(pipe, "get", "show one pipeline run")
    p.add_argument("uuid")
    p.set_defaults(func=cmd_pipeline_get)
    p = leaf(pipe, "steps", "list the steps of a run")
    p.add_argument("uuid")
    p.set_defaults(func=cmd_pipeline_steps)
    p = leaf(pipe, "log", "print one step's log")
    p.add_argument("uuid")
    p.add_argument("step_uuid", metavar="STEP_UUID")
    p.set_defaults(func=cmd_pipeline_log)
    p = leaf(pipe, "run", "start a pipeline (write)")
    p.add_argument("--branch", required=True, metavar="BRANCH")
    p.add_argument("--pattern", metavar="NAME", help="custom pipeline name")
    p.set_defaults(func=cmd_pipeline_run)
    p = leaf(pipe, "stop", "stop a running pipeline (write)")
    p.add_argument("uuid")
    p.set_defaults(func=cmd_pipeline_stop)

    # mcp-serve -- no shared globals: it needs no repo and no credentials
    p = top.add_parser(
        "mcp-serve", help="serve bb to Claude apps over MCP on 127.0.0.1"
    )
    p.add_argument(
        "--port", type=int, default=MCP_PORT, help="default: %d" % MCP_PORT
    )
    p.add_argument(
        "--init-secret", action="store_true", help="create the secret if missing"
    )
    p.add_argument(
        "--rotate-secret", action="store_true", help="replace the secret"
    )
    p.add_argument(
        "--show-header",
        action="store_true",
        help="print the Authorization line (only to a terminal)",
    )

    # api
    p = leaf(top, "api", "any request, relative to " + API_BASE)
    p.add_argument("method", metavar="METHOD")
    p.add_argument("path", metavar="PATH")
    p.add_argument("--data", metavar="JSON")
    p.add_argument("--data-file", metavar="FILE", help="'-' reads stdin")
    p.add_argument("--query", action="append", metavar="KEY=VALUE")
    p.add_argument("--raw", action="store_true", help="print the body as text")
    p.add_argument(
        "--paginate", action="store_true", help="follow every 'next' link (GET only)"
    )
    p.set_defaults(func=cmd_api)

    return parser


# ==========================================================================
# mcp-serve: bb as an MCP server, spoken over HTTP on the loopback interface
# ==========================================================================
def _env_int(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        raise SystemExit("%s must be a number" % name)


def _env_list(name):
    return tuple(h.strip().lower() for h in os.environ.get(name, "").split(",") if h.strip())


# Keep the bind address on the loopback interface and put a tunnel or reverse
# proxy in front; the server has no TLS of its own.
MCP_BIND = os.environ.get("BB_MCP_BIND", "").strip() or "127.0.0.1"
MCP_PORT = _env_int("BB_MCP_PORT", 8765)
MCP_SECRET_PATH = os.path.expanduser(
    os.environ.get("BB_MCP_SECRET_FILE", "").strip()
    or os.path.join("~", ".config", "bb", "mcp-secret")
)
MCP_VERSIONS = ("2025-03-26", "2025-06-18", "2025-11-25")
MCP_NEWEST = MCP_VERSIONS[-1]
# Public host names (e.g. a Cloudflare Tunnel hostname) this server answers to.
MCP_TUNNEL_HOSTS = _env_list("BB_MCP_PUBLIC_HOSTS")
MCP_KNOWN_ORIGINS = ("https://claude.ai", "https://claude.com")
MCP_MAX_BODY = 1024 * 1024
MCP_MAX_OUTPUT = 100000
MCP_COMMAND_TIMEOUT = 90
MCP_MAX_CONCURRENT = 4
MCP_SOCKET_TIMEOUT = 30
MCP_FAIL_LIMIT = 10
MCP_FAIL_WINDOW = 60.0
MCP_LOCKOUT = 60.0

# The read-only set: the commands bb_read runs. Everything else goes to
# bb_write.
READ_ONLY = frozenset(
    [
        ("whoami", None),
        ("scopes", None),
        ("repo", "get"),
        ("repo", "list"),
        ("branch", "list"),
        ("branch", "get"),
        ("tag", "list"),
        ("tag", "get"),
        ("commit", "get"),
        ("commit", "list"),
        ("diff", None),
        ("diffstat", None),
        ("file", "get"),
        ("file", "list"),
        ("pr", "list"),
        ("pr", "get"),
        ("pr", "diff"),
        ("pr", "diffstat"),
        ("pr", "commits"),
        ("pr", "activity"),
        ("pr", "comments"),
        ("pr", "tasks"),
        ("pr", "statuses"),
        ("pipeline", "list"),
        ("pipeline", "get"),
        ("pipeline", "steps"),
        ("pipeline", "log"),
        ("api", None),  # only GET, and only without a body -- see classify_args
    ]
)

# Options that would make bb read a file on this machine. '-' would read the
# server's own stdin, which is the JSON-RPC channel's sibling.
MCP_FILE_OPTIONS = (
    ("description_file", "--description-file"),
    ("text_file", "--text-file"),
    ("message_file", "--message-file"),
    ("data_file", "--data-file"),
)

MCP_INSTRUCTIONS = """\
bb is a command-line client for Bitbucket Cloud, offered here as two tools.

bb_read runs read-only commands. bb_write runs everything that changes something.
Both take one argument, args: the words that would follow `bb` on a command line.
Example: {"args": ["pr", "list", "--state", "OPEN", "--brief"]}

%s
Output is pretty JSON; --brief gives one short line per item; --all follows
every page, and without it you get the first page plus a note saying how many
remain.

Read-only commands (bb_read)
  whoami | scopes
  repo get | repo list [WORKSPACE]
  branch list [--name TEXT] | branch get NAME
  tag list | tag get NAME
  commit get HASH | commit list [REVISION] [--path P]
  diff SPEC | diffstat SPEC
  file get REF PATH | file list REF [PATH]
  pr list [--state OPEN|MERGED|DECLINED|SUPERSEDED] [--author TEXT] [--source B]
          [--dest B] [--title TEXT]
  pr get ID | pr diff ID | pr diffstat ID | pr commits ID | pr activity ID
  pr comments ID | pr tasks ID | pr statuses ID
  pipeline list [--branch B] | pipeline get UUID | pipeline steps UUID
  pipeline log UUID STEP_UUID
  api GET PATH [--query k=v] [--raw] [--paginate]

Commands that change something (bb_write)
  branch create NAME --from REF | branch delete NAME
  tag create NAME --from REF [--message TEXT] | tag delete NAME
  pr create --source B --dest B --title T [--description TEXT] [--draft]
            [--reviewer ACCOUNT_ID] [--close-source-branch]
  pr update ID [--title T] [--description TEXT] [--dest B]
  pr comment ID --text TEXT [--reply-to COMMENT_ID]
  pr comment-edit ID COMMENT_ID --text TEXT | pr comment-delete ID COMMENT_ID
  pr task-create ID --text TEXT | pr task-update ID TASK_ID [--text TEXT]
            [--state RESOLVED|UNRESOLVED] | pr task-delete ID TASK_ID
  pr approve ID | pr unapprove ID | pr request-changes ID
  pr remove-request-changes ID | pr decline ID
  pr merge ID [--strategy squash|merge_commit|fast_forward] [--message TEXT]
  pipeline run --branch B [--pattern NAME] | pipeline stop UUID
  api POST|PUT|DELETE PATH [--data JSON]

Examples
  {"args": ["pr", "list", "--state", "OPEN", "--brief"]}
  {"args": ["pr", "diffstat", "42", "--brief"]}
  {"args": ["branch", "list", "--name", "feature/", "--brief"]}
  {"args": ["pr", "comment", "42", "--text", "Looks good to me."]}
  {"args": ["api", "GET", "/repositories/WORKSPACE/SLUG/pullrequests"]}

Worth knowing
  Long text goes inline, with --text, --description or --message. The options that
  read a file (--text-file and its friends) are not available through these tools.
  diff A..B is source..destination, the opposite order to git diff, and compares
  against the merge base; add --two-dot to compare the two ends directly.
  pr update works only on an OPEN pull request and resends the whole document.
  Add --dry-run to any write to see the exact request without sending it.
  A refused command says which of the two tools to use instead.
""" % (
    ("The default repository is %s. Add --repo WORKSPACE/SLUG for\nanother one."
     % DEFAULT_REPO)
    if DEFAULT_REPO
    else "There is no default repository: add --repo WORKSPACE/SLUG to every\n"
    "command that works on one."
)

MCP_TOOL_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "args": {
            "type": "array",
            "items": {"type": "string"},
            "description": 'The words after `bb`, for example ["pr", "list", "--brief"].',
        }
    },
    "required": ["args"],
    "additionalProperties": False,
}

MCP_TOOLS = [
    {
        "name": "bb_read",
        "title": "bb (read-only)",
        "description": "Run a read-only bb command against Bitbucket Cloud: pull "
        "requests, branches, tags, commits, diffs, files and pipelines. Nothing "
        "it does changes anything.",
        "inputSchema": MCP_TOOL_INPUT_SCHEMA,
        "annotations": {"title": "bb (read-only)", "readOnlyHint": True},
    },
    {
        "name": "bb_write",
        "title": "bb (makes changes)",
        "description": "Run a bb command that changes something on Bitbucket Cloud: "
        "create or edit a pull request, comment, approve, decline, merge, create or "
        "delete a branch or tag, or start a pipeline.",
        "inputSchema": MCP_TOOL_INPUT_SCHEMA,
        "annotations": {
            "title": "bb (makes changes)",
            "readOnlyHint": False,
            "destructiveHint": True,
        },
    },
]

_MCP_SLOTS = threading.BoundedSemaphore(MCP_MAX_CONCURRENT)


# ---- small helpers -------------------------------------------------------
def bb_real_path():
    """The bb file this process is running from, with symlinks resolved."""
    return os.path.realpath(os.path.abspath(__file__))


def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def all_leaf_commands():
    """Every (command, subcommand) pair build_parser() defines."""
    parser = build_parser()
    leaves = set()
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for name, sub in action.choices.items():
            inner = [a for a in sub._actions if isinstance(a, argparse._SubParsersAction)]
            if inner:
                for deeper in inner:
                    for sub_name in deeper.choices:
                        leaves.add((name, sub_name))
            else:
                leaves.add((name, None))
    return leaves


def mcp_group_help(command):
    """The help text argparse would print for a group, or for bb itself."""
    parser = build_parser()
    buffer = io.StringIO()
    saved_out, saved_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = buffer, buffer
    try:
        try:
            parser.parse_args([command, "--help"] if command else ["--help"])
        except SystemExit:
            pass
        except Exception:  # pragma: no cover - defensive
            pass
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err
    return buffer.getvalue()


# ---- classification ------------------------------------------------------
def classify_args(argv):
    """Work out what a list of bb arguments would do.

    Returns a dict with a 'kind' of:
      help    -- --help/--version; 'text' is what bb would have printed
      usage   -- bb would reject these arguments; 'text' explains
      blocked -- refused here whatever the tool; 'reason' says why
      read    -- a read-only command
      write   -- a command that changes something

    Everything is decided from the PARSED namespace, never from the spelling of
    the arguments, because argparse accepts abbreviations such as --text-fi.
    """
    parser = build_parser()
    buffer = io.StringIO()
    saved_out, saved_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = buffer, buffer
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
            text = buffer.getvalue()
            return {"kind": "help" if code == 0 else "usage", "text": text}
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err

    command = getattr(args, "command", None)
    subcommand = getattr(args, "subcommand", None)

    if command == "mcp-serve":
        return {
            "kind": "blocked",
            "reason": "mcp-serve runs this server itself, and --show-header would "
            "print the shared secret.",
        }

    if not getattr(args, "func", None):
        return {"kind": "usage", "text": mcp_group_help(command)}

    for dest, flag in MCP_FILE_OPTIONS:
        if getattr(args, dest, None):
            return {
                "kind": "blocked",
                "reason": "%s reads a file on the machine bb runs on. Pass the text "
                "inline instead (--text, --description, --message, or --data for "
                "api)." % flag,
            }

    if getattr(args, "confirm_delete_repository", None):
        return {
            "kind": "blocked",
            "reason": "--confirm-delete-repository deletes an entire repository. "
            "That can only be done from the machine itself.",
        }

    if command == "api":
        path = (getattr(args, "path", "") or "").strip()
        if path.lower().startswith(("http://", "https://")):
            return {
                "kind": "blocked",
                "reason": "an absolute URL could send the Bitbucket credentials to "
                "another host. Use a path such as /repositories/WORKSPACE/SLUG.",
            }
        method = (getattr(args, "method", "") or "").upper()
        if getattr(args, "paginate", False) and method != "GET":
            return {
                "kind": "usage",
                "text": "--paginate only ever makes GET requests, so bb would "
                "quietly ignore %s. Drop one of the two." % method,
            }
        read = method == "GET" and getattr(args, "data", None) is None
        return {"kind": "read" if read else "write"}

    return {"kind": "read" if (command, subcommand) in READ_ONLY else "write"}


# ---- running a command ---------------------------------------------------
def mcp_redact(text, secret=None):
    """Replace anything secret. Always called before the output is capped."""
    if not text:
        return text
    values = []
    try:
        auth = load_auth()
        values.extend(auth.secrets())
    except BbError:
        pass
    except Exception:  # pragma: no cover - a broken ~/.netrc must not leak
        pass
    if secret:
        values.append(secret)
    for value in values:
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def mcp_cap(text):
    if len(text) <= MCP_MAX_OUTPUT:
        return text
    return text[:MCP_MAX_OUTPUT] + (
        "\n\n[cut after %d of %d characters. Ask for less: add --brief, narrow with "
        "--path or --query, or leave out --all.]" % (MCP_MAX_OUTPUT, len(text))
    )


def mcp_command_text(code, stdout, stderr):
    parts = []
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append("stderr:\n" + stderr)
    if code:
        parts.append("exit code: %d" % code)
    return "\n".join(parts)


def mcp_run_bb(argv, timeout=MCP_COMMAND_TIMEOUT):
    """Run bb in its own process group. Returns (code, stdout, stderr).

    code is None when the command ran out of time. Popen rather than
    subprocess.run because run() reaps the child before raising, leaving
    nothing to kill by group.
    """
    proc = subprocess.Popen(
        [sys.executable, bb_real_path()] + list(argv),
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):  # pragma: no cover
            proc.kill()
        try:
            proc.communicate(timeout=10)
        except Exception:  # pragma: no cover
            pass
        return None, "", ""
    return proc.returncode, stdout, stderr


# ---- JSON-RPC ------------------------------------------------------------
def mcp_tool_result(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}


def mcp_response(msg_id, result=None, error=None):
    reply = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        reply["error"] = error
    else:
        reply["result"] = result
    return reply


def mcp_error_object(code, message):
    return {"code": code, "message": message}


def mcp_tools_call(params, state, log):
    """tools/call. Only an unknown tool or malformed params is a protocol error."""
    if not isinstance(params, dict):
        return mcp_error_object(-32602, "params must be an object"), None
    name = params.get("name")
    if not isinstance(name, str):
        return mcp_error_object(-32602, "tools/call needs a string name"), None
    arguments = params.get("arguments")
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return mcp_error_object(-32602, "arguments must be an object"), None
    if name not in ("bb_read", "bb_write"):
        return mcp_error_object(-32602, "unknown tool: %s" % name), None

    log["tool"] = name

    argv = arguments.get("args")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return None, mcp_tool_result(
            'args must be an array of strings, for example {"args": ["pr", "list"]}.',
            True,
        )
    if not argv:
        return None, mcp_tool_result(
            'args is empty. Give the words that follow bb, for example '
            '{"args": ["pr", "list", "--brief"]}.',
            True,
        )

    log["args"] = " ".join(argv[:2])

    if state.get("digest"):
        try:
            current = file_digest(bb_real_path())
        except OSError:
            current = None
        if current != state["digest"]:
            log["stale"] = "yes"
            return None, mcp_tool_result(
                "bb changed on disk since bb-mcp started; restart bb-mcp.", True
            )

    verdict = classify_args(argv)
    kind = verdict["kind"]

    if kind == "help":
        return None, mcp_tool_result(verdict["text"] or "(no help text)", False)
    if kind == "usage":
        return None, mcp_tool_result(
            "bb could not use those arguments.\n\n" + (verdict["text"] or ""), True
        )
    if kind == "blocked":
        return None, mcp_tool_result("Refused: " + verdict["reason"], True)

    if kind == "read" and name == "bb_write":
        return None, mcp_tool_result(
            "That is a read-only command. Call it with bb_read instead, so it does "
            "not need approval.",
            True,
        )
    if kind == "write" and name == "bb_read":
        return None, mcp_tool_result(
            "That command changes something, so bb_read will not run it. Use "
            "bb_write instead.",
            True,
        )

    if not _MCP_SLOTS.acquire(blocking=False):
        return None, mcp_tool_result("busy, retry shortly", True)
    try:
        code, stdout, stderr = mcp_run_bb(argv)
    finally:
        _MCP_SLOTS.release()

    if code is None:
        log["exit"] = "timeout"
        return None, mcp_tool_result(
            "timed out after %d seconds" % MCP_COMMAND_TIMEOUT, True
        )

    log["exit"] = code
    text = mcp_command_text(code, stdout, stderr)
    text = mcp_redact(text, state.get("secret"))
    text = mcp_cap(text)
    return None, mcp_tool_result(text, code != 0)


def mcp_handle_message(msg, state, log):
    """One JSON-RPC message in, one reply out (or None for a notification)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return mcp_response(None, error=mcp_error_object(-32600, "invalid request"))
    method = msg.get("method")
    has_id = "id" in msg
    msg_id = msg.get("id")

    if not isinstance(method, str):
        if has_id and ("result" in msg or "error" in msg):
            return None  # a response to us; nothing to answer
        return mcp_response(msg_id, error=mcp_error_object(-32600, "invalid request"))

    log["method"] = method
    params = msg.get("params")

    if method == "initialize":
        requested = None
        if isinstance(params, dict):
            requested = params.get("protocolVersion")
            client = params.get("clientInfo")
            if isinstance(client, dict):
                log["client_name"] = client.get("name")
                log["client_version"] = client.get("version")
        log["asked_version"] = requested
        version = requested if requested in MCP_VERSIONS else MCP_NEWEST
        result = {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "bb", "version": __version__},
            "instructions": MCP_INSTRUCTIONS,
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": MCP_TOOLS}
    elif method == "prompts/list":
        result = {"prompts": []}
    elif method == "resources/list":
        result = {"resources": []}
    elif method == "resources/templates/list":
        result = {"resourceTemplates": []}
    elif method == "tools/call":
        error, result = mcp_tools_call(params, state, log)
        if error is not None:
            return mcp_response(msg_id, error=error) if has_id else None
    else:
        if not has_id:
            return None
        return mcp_response(
            msg_id, error=mcp_error_object(-32601, "method not found: %s" % method)
        )

    if not has_id:
        return None  # a notification: acknowledged, but nothing to say
    return mcp_response(msg_id, result=result)


# ---- failed-secret tracking ---------------------------------------------
class FailTracker(object):
    """Counts wrong secrets per client and locks that client out for a while."""

    def __init__(self):
        self._lock = threading.Lock()
        self._failures = {}
        self._locked_until = {}

    def record_failure(self, client, now):
        with self._lock:
            recent = [t for t in self._failures.get(client, []) if now - t < MCP_FAIL_WINDOW]
            recent.append(now)
            self._failures[client] = recent
            if len(recent) > MCP_FAIL_LIMIT:
                self._locked_until[client] = now + MCP_LOCKOUT
                return True
            return self._locked_until.get(client, 0.0) > now

    def clear(self, client):
        with self._lock:
            self._failures.pop(client, None)
            self._locked_until.pop(client, None)


# ---- logging -------------------------------------------------------------
def mcp_log_value(value):
    text = "".join(ch for ch in str(value) if ch >= " " and ch != "\x7f")
    if len(text) > 200:
        text = text[:200]
    if text == "" or " " in text or '"' in text or "=" in text:
        text = '"%s"' % text.replace('"', "'")
    return text


def mcp_log(fields):
    parts = ["%s=%s" % (key, mcp_log_value(value)) for key, value in fields.items()
             if value is not None and value != ""]
    sys.stderr.write(" ".join(parts) + "\n")
    sys.stderr.flush()


# ---- the HTTP surface ----------------------------------------------------
class _TooBig(Exception):
    pass


class _BadBody(Exception):
    pass


class McpHandler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0 on purpose: every response closes the connection, so rejecting a
    # request without reading its body can never confuse the next one.
    server_version = "bb-mcp"
    sys_version = ""
    timeout = MCP_SOCKET_TIMEOUT

    # -- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *a):  # the default one-liner; we log our own
        return

    def _state(self):
        return self.server.bb_state

    def _client(self):
        forwarded = self.headers.get("CF-Connecting-IP")
        if forwarded and forwarded.strip():
            return forwarded.strip()[:200]
        return self.client_address[0] if self.client_address else "?"

    def _reply(self, status, payload=None, headers=None):
        body = b""
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)
        return status

    # -- the checks, in order ---------------------------------------------
    def _host_ok(self):
        host = (self.headers.get("Host") or "").strip()
        port = self.server.server_address[1]
        allowed = set(MCP_TUNNEL_HOSTS)
        allowed.add("127.0.0.1:%d" % port)
        allowed.add("localhost:%d" % port)
        allowed.update(self._state().get("extra_hosts", ()))
        return host in allowed, host

    def _declared_too_big(self):
        raw = self.headers.get("Content-Length")
        if raw is None:
            return False
        try:
            return int(raw) > MCP_MAX_BODY
        except (TypeError, ValueError):
            return False

    def _secret_ok(self):
        offered = self.headers.get("Authorization") or ""
        expected = "Bearer " + self._state()["secret"]
        return hmac.compare_digest(offered, expected)

    def _read_body(self):
        encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in encoding:
            return self._read_chunked(), "chunked"
        raw = self.headers.get("Content-Length")
        if raw is None:
            return b"", "none"
        try:
            length = int(raw)
        except (TypeError, ValueError):
            raise _BadBody()
        if length > MCP_MAX_BODY:
            raise _TooBig()
        if length <= 0:
            return b"", "content-length 0"
        return self.rfile.read(length), "content-length %d" % length

    def _read_chunked(self):
        pieces = []
        total = 0
        while True:
            line = self.rfile.readline(65536)
            if not line:
                raise _BadBody()
            head = line.strip().split(b";")[0]
            try:
                size = int(head, 16)
            except ValueError:
                raise _BadBody()
            if size < 0:
                raise _BadBody()
            if size == 0:
                while True:  # trailers, up to the blank line
                    trailer = self.rfile.readline(65536)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                break
            total += size
            if total > MCP_MAX_BODY:
                raise _TooBig()
            pieces.append(self.rfile.read(size))
            self.rfile.read(2)  # the CRLF that ends the chunk
        return b"".join(pieces)

    # -- verbs -------------------------------------------------------------
    def do_POST(self):
        self._serve("POST")

    def do_GET(self):
        self._serve("GET")

    def do_DELETE(self):
        self._serve("DELETE")

    def do_HEAD(self):
        self._serve("HEAD")

    def do_OPTIONS(self):
        self._serve("OPTIONS")

    def _serve(self, verb):
        started = time.time()
        origin = self.headers.get("Origin")
        log = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "client": self._client(),
            "verb": verb,
            "path": self.path,
            "origin": origin if origin is not None else "-",
            "ua": self.headers.get("User-Agent") or "-",
            "accept": self.headers.get("Accept") or "-",
            "mcp_version_header": self.headers.get("MCP-Protocol-Version") or "-",
        }
        if origin is None or origin.rstrip("/") not in MCP_KNOWN_ORIGINS:
            log["origin_unknown"] = "yes"
        try:
            status = self._route(verb, log)
        except Exception as exc:  # pragma: no cover - never leak a traceback
            log["error"] = type(exc).__name__
            try:
                status = self._reply(500, {"error": "internal error"})
            except Exception:
                status = 500
        log["status"] = status
        log["ms"] = int((time.time() - started) * 1000)
        ordered = {}
        for key in ("time", "client", "status", "verb", "path", "method", "tool",
                    "args", "exit", "ms", "origin", "origin_unknown", "ua", "accept",
                    "mcp_version_header", "body", "asked_version", "client_name",
                    "client_version", "stale", "error"):
            if key in log:
                ordered[key] = log[key]
        mcp_log(ordered)

    def _route(self, verb, log):
        path = urllib.parse.urlsplit(self.path).path

        host_ok, host = self._host_ok()
        if not host_ok:
            log["host"] = host or "-"
            return self._reply(421, {"error": "misdirected request"})

        # /.well-known/* answers without the secret, so claude.ai does not
        # mistake this for an OAuth-protected server.
        if path.startswith("/.well-known/") or path == "/.well-known":
            return self._reply(404, {"error": "not found"})

        if self._declared_too_big():
            return self._reply(413, {"error": "request too large"})

        state = self._state()
        client = self._client()
        now = time.time()
        if not self._secret_ok():
            locked = state["tracker"].record_failure(client, now)
            if locked:
                return self._reply(429, {"error": "too many attempts"},
                                   {"Retry-After": str(int(MCP_LOCKOUT))})
            return self._reply(401, {"error": "unauthorized"})
        state["tracker"].clear(client)

        if path != "/mcp":
            return self._reply(404, {"error": "not found"})

        if verb != "POST":
            return self._reply(405, {"error": "method not allowed"}, {"Allow": "POST"})

        try:
            raw, framing = self._read_body()
        except _TooBig:
            return self._reply(413, {"error": "request too large"})
        except _BadBody:
            return self._reply(
                400,
                mcp_response(None, error=mcp_error_object(-32700, "could not read the body")),
            )
        log["body"] = framing

        if not raw.strip():
            return self._reply(
                400, mcp_response(None, error=mcp_error_object(-32700, "empty body"))
            )
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._reply(
                400, mcp_response(None, error=mcp_error_object(-32700, "parse error"))
            )

        batched = isinstance(payload, list)
        messages = payload if batched else [payload]
        if batched and not messages:
            return self._reply(
                400, mcp_response(None, error=mcp_error_object(-32600, "invalid request"))
            )

        replies = []
        for message in messages:
            reply = mcp_handle_message(message, state, log)
            if reply is not None:
                replies.append(reply)

        if not replies:
            return self._reply(202)

        bad = any(
            (reply.get("error") or {}).get("code") in (-32700, -32600) for reply in replies
        )
        body = replies if batched else replies[0]
        return self._reply(400 if bad else 200, body)


# ---- the secret ----------------------------------------------------------
def mcp_secret_file():
    return MCP_SECRET_PATH


def mcp_write_secret(rotate):
    path = mcp_secret_file()
    folder = os.path.dirname(path)
    if not os.path.isdir(folder):
        os.makedirs(folder, mode=0o700)
    os.chmod(folder, 0o700)
    if os.path.exists(path) and not rotate:
        out(path)
        return 0
    temporary = path + ".tmp"
    handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(handle, "w") as fh:
            fh.write(secrets.token_urlsafe(32) + "\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)
    out(path)
    if rotate:
        out("restart bb-mcp, then remove and re-add the connector in claude.ai")
    return 0


def mcp_read_secret():
    path = mcp_secret_file()
    if not os.path.exists(path):
        raise BbError("No secret yet. Run: bb mcp-serve --init-secret", 2)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode != 0o600:
        raise BbError(
            "%s must be mode 600, but it is %o. Fix that, then start again."
            % (path, mode),
            2,
        )
    with open(path) as fh:
        secret = fh.read().strip()
    if not secret:
        raise BbError("The secret file is empty. Run: bb mcp-serve --rotate-secret", 2)
    return secret


# ---- the subcommand ------------------------------------------------------
def make_mcp_server(port, secret, digest=None, extra_hosts=()):
    server = http.server.ThreadingHTTPServer((MCP_BIND, port), McpHandler)
    server.daemon_threads = True
    server.bb_state = {
        "secret": secret,
        "digest": digest,
        "tracker": FailTracker(),
        "extra_hosts": tuple(extra_hosts),
    }
    return server


def cmd_mcp_serve(args):
    if args.init_secret:
        return mcp_write_secret(rotate=False)
    if args.rotate_secret:
        return mcp_write_secret(rotate=True)
    if args.show_header:
        if not sys.stdout.isatty():
            note(
                "--show-header prints a secret, so it only runs when stdout is a "
                "terminal. Run it yourself, in your own terminal."
            )
            return 2
        out("Bearer " + mcp_read_secret())
        return 0

    secret = mcp_read_secret()
    path = bb_real_path()
    server = make_mcp_server(args.port, secret, digest=file_digest(path))
    mcp_log(
        {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "event": "listening",
            "address": "%s:%d" % (MCP_BIND, args.port),
            "bb": path,
            "version": __version__,
        }
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        pass
    finally:
        server.server_close()
    return 0


# ==========================================================================
# entry point
# ==========================================================================
def main(argv=None, transport=None, auth=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # mcp-serve is dispatched here, before load_auth(), so --init-secret works
    # with no ~/.netrc, and so its exit code reaches the shell.
    if getattr(args, "command", None) == "mcp-serve":
        return cmd_mcp_serve(args)

    if not getattr(args, "func", None):
        parser.print_help()
        return 2

    if auth is None:
        auth = load_auth()
    register_secrets(auth)

    client = Client(
        auth,
        repo=args.repo,
        transport=transport,
        dry_run=args.dry_run,
        timeout=args.timeout,
        confirm_delete_repository=args.confirm_delete_repository,
    )
    args.func(client, args)
    return 0


def run(argv=None):
    try:
        return main(argv)
    except HttpError as exc:
        for line in describe_error(exc):
            note(line)
        return exc.code
    except BbError as exc:
        note(exc.message)
        return exc.code
    except BrokenPipeError:  # pragma: no cover
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:  # pragma: no cover
        note("")
        return 130


if __name__ == "__main__":
    sys.exit(run())
