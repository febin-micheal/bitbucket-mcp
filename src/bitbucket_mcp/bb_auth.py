#!/usr/bin/env python3
"""bb-auth -- store and check the Atlassian API token used by `bb`.

The token is written to ~/.netrc under `machine api.bitbucket.org` and is never
printed, logged, echoed or passed on a command line.

Usage:
    bb-auth            interactive: ask for email + token, save, then check
    bb-auth --check    check the stored credentials only (no prompts)
    bb-auth --show     print the stored login (email) only, never the token
"""

import argparse
import base64
import json
import netrc
import os
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from getpass import getpass

MACHINE = "api.bitbucket.org"
API = "https://api.bitbucket.org/2.0"
# Optional: a repository to test read access on, as WORKSPACE/SLUG.
DEFAULT_REPO = os.environ.get("BB_DEFAULT_REPO", "").strip()
NETRC = os.path.join(os.path.expanduser("~"), ".netrc")


# --------------------------------------------------------------------------
# reading (via the stdlib netrc module only)
# --------------------------------------------------------------------------
def read_login():
    """Return the stored login for api.bitbucket.org, or None. Never the token."""
    try:
        auth = netrc.netrc().authenticators(MACHINE)
    except FileNotFoundError:
        return None
    except netrc.NetrcParseError as exc:
        print("~/.netrc could not be parsed: %s" % exc, file=sys.stderr)
        return None
    if not auth:
        return None
    return auth[0] or None


def read_auth():
    """Return (login, token) for api.bitbucket.org, or None."""
    try:
        auth = netrc.netrc().authenticators(MACHINE)
    except FileNotFoundError:
        return None
    except netrc.NetrcParseError as exc:
        print("~/.netrc could not be parsed: %s" % exc, file=sys.stderr)
        return None
    if not auth or not auth[2]:
        return None
    return auth[0], auth[2]


# --------------------------------------------------------------------------
# writing (raw text is handled in memory only, never printed)
# --------------------------------------------------------------------------
def _tokens(text):
    """Yield (start, end, value) for every whitespace-separated token."""
    i, n = 0, len(text)
    while i < n:
        if text[i].isspace():
            i += 1
            continue
        j = i
        while j < n and not text[j].isspace():
            j += 1
        yield i, j, text[i:j]
        i = j


def _entries(text):
    """Yield (start, end, kind, name) for each top-level netrc entry.

    Mirrors the stdlib parser closely enough to find entry boundaries so the
    rest of the file can be preserved byte for byte.
    """
    toks = list(_tokens(text))
    out = []
    i = 0
    while i < len(toks):
        start, end, val = toks[i]
        if val.startswith("#"):
            nl = text.find("\n", start)
            i += 1
            while i < len(toks) and (nl == -1 or toks[i][0] < nl):
                i += 1
            continue
        if val in ("machine", "default", "macdef"):
            if val == "machine":
                name = toks[i + 1][2] if i + 1 < len(toks) else ""
                i += 2
            elif val == "default":
                name = "default"
                i += 1
            else:  # macdef: body runs to the next blank line
                name = toks[i + 1][2] if i + 1 < len(toks) else ""
                i += 2
                blank = text.find("\n\n", end)
                stop = len(text) if blank == -1 else blank + 1
                while i < len(toks) and toks[i][0] < stop:
                    i += 1
                out.append([start, stop, val, name])
                continue
            # consume followers until the next top-level keyword
            while i < len(toks):
                t_start, _t_end, t_val = toks[i]
                if t_val.startswith("#") or t_val in ("machine", "default", "macdef"):
                    break
                i += 1
            stop = toks[i][0] if i < len(toks) else len(text)
            out.append([start, stop, val, name])
            continue
        # unknown top-level token: skip it rather than crash
        i += 1
    return out


def validate_token(token):
    """Reject tokens ~/.netrc cannot represent. Never echoes the token."""
    if not token:
        return "the token is empty"
    if any(ch.isspace() for ch in token):
        return "the token contains whitespace -- copy it again without line breaks"
    if token.startswith("#"):
        return "the token starts with '#', which ~/.netrc treats as a comment"
    if token[0] in "'\"":
        return "the token starts with a quote character, which ~/.netrc cannot store"
    return None


def write_entry(email, token, path=NETRC):
    """Replace only the api.bitbucket.org entry. Atomic, mode 600."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        text = ""

    for start, stop, kind, name in reversed(_entries(text)):
        if kind == "machine" and name == MACHINE:
            text = text[:start] + text[stop:]

    if text and not text.endswith("\n"):
        text += "\n"
    text += "machine %s\n    login %s\n    password %s\n" % (MACHINE, email, token)

    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".netrc.", suffix=".tmp")
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


# --------------------------------------------------------------------------
# checking
# --------------------------------------------------------------------------
def _get(path, login, token):
    req = urllib.request.Request(API + path, method="GET")
    blob = base64.b64encode(("%s:%s" % (login, token)).encode("utf-8")).decode("ascii")
    req.add_header("Authorization", "Basic " + blob)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "bb-auth/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return None, str(exc.reason)


def _message(body):
    try:
        data = json.loads(body)
    except ValueError:
        return body.strip()[:400]
    err = data.get("error") or {}
    msg = err.get("message") or data.get("error_description") or ""
    detail = err.get("detail")
    if detail:
        msg = "%s -- %s" % (msg, detail)
    return msg or body.strip()[:400]


def check():
    """Return 0 on success. Prints a one-line result. Never prints the token."""
    auth = read_auth()
    if not auth:
        print(
            "No credentials for %s in ~/.netrc. Run: bb-auth" % MACHINE,
            file=sys.stderr,
        )
        return 2
    login, token = auth

    status, body = _get("/user", login, token)
    if status != 200:
        where = "HTTP %s" % status if status else "network error"
        print("GET /user failed: %s: %s" % (where, _message(body)), file=sys.stderr)
        return 1
    try:
        name = json.loads(body).get("display_name") or login
    except ValueError:
        name = login

    if not DEFAULT_REPO:
        print("OK: %s (set BB_DEFAULT_REPO to also check a repository)" % name)
        return 0

    status, body = _get("/repositories/" + DEFAULT_REPO, login, token)
    if status != 200:
        where = "HTTP %s" % status if status else "network error"
        print(
            "GET /repositories/%s failed: %s: %s" % (DEFAULT_REPO, where, _message(body)),
            file=sys.stderr,
        )
        return 1

    print("OK: %s, repo %s readable" % (name, DEFAULT_REPO))
    return 0


# --------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bb-auth",
        description="Store and check the Atlassian API token used by bb. "
        "The token is never printed.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--check", action="store_true", help="check the stored credentials and exit"
    )
    group.add_argument(
        "--show", action="store_true", help="print the stored login (never the token)"
    )
    args = parser.parse_args(argv)

    if args.check:
        return check()

    if args.show:
        login = read_login()
        print(login if login else "(no %s entry in ~/.netrc)" % MACHINE)
        return 0 if login else 1

    if not sys.stdin.isatty():
        print(
            "bb-auth needs a terminal so the token stays hidden. "
            "Run it in a normal terminal, not inside an agent.",
            file=sys.stderr,
        )
        return 2

    current = read_login()
    prompt = "Atlassian email"
    if current:
        prompt += " [%s]" % current
    email = input(prompt + ": ").strip() or (current or "")
    if not email:
        print("An email is required.", file=sys.stderr)
        return 2

    print(
        "Create the token at "
        "https://id.atlassian.com/manage-profile/security/api-tokens "
        "(Create API token with scopes -> app: Bitbucket -> select every scope)."
    )
    token = getpass("Atlassian API token (hidden): ").strip()
    problem = validate_token(token)
    if problem:
        print("Not saved: %s." % problem, file=sys.stderr)
        return 2

    write_entry(email, token, NETRC)

    stored = read_auth()
    if not stored or stored[1] != token:
        print(
            "The token was written but could not be read back from ~/.netrc. "
            "Check the file for a syntax problem.",
            file=sys.stderr,
        )
        return 1
    del token, stored

    print("Saved to ~/.netrc (mode 600). Checking...")
    return check()


def cli():
    try:
        return main()
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(cli())
