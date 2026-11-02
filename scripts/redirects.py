# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT

"""The finish URI the demo registers, and the one it sends, are the same address.

A loopback URI follows the port the demo listens on. Any other host is left as written.
"""

from urllib.parse import urlsplit, urlunsplit

LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


def port_number(value):
    raw = str(value if value is not None else "").strip()
    if not raw:
        return None
    try:
        port = int(raw)
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _hostname(url):
    parts = urlsplit(url)
    host = parts.hostname or ""
    if host.startswith("[") and host.endswith("]"):
        shown = host
    elif ":" in host:
        shown = f"[{host}]"
    else:
        shown = host
    return parts, shown


def on_port(url, port):
    """Replace the port of a loopback URL. Anything else, including an unparseable value, is unchanged."""
    try:
        parts, host = _hostname(url)
        if host not in LOOPBACK and (parts.hostname or "") not in LOOPBACK:
            return url
        netloc = f"{host}:{int(port)}"
        path = parts.path or "/"
        return urlunsplit((parts.scheme, netloc, path, parts.query, parts.fragment))
    except Exception:
        return url


def redirects_for(finish_uri, display_uri, public_url, public_url_given, port):
    """The finish and display URIs to register.

    An explicit public URL replaces the origin and keeps the path.
    Otherwise `port` moves a loopback URI onto the port the demo listens on.
    """
    def listed(finish, display):
        out = {"finishUri": finish}
        if display:
            out["displayUri"] = display
        return out

    if public_url_given and public_url:
        base = urlsplit(public_url if public_url.endswith("/") else f"{public_url}/")

        def move(value):
            if not value:
                return value
            nxt = urlsplit(value)
            return urlunsplit((base.scheme, base.netloc, nxt.path or "/", nxt.query, nxt.fragment))

        return listed(move(finish_uri), move(display_uri))
    if port:
        return listed(on_port(finish_uri, port), on_port(display_uri, port) if display_uri else display_uri)
    return listed(finish_uri, display_uri)


def demo_port(env_port, container_port):
    """The container's PORT wins when it is a port. Otherwise the environment. An empty value is absent."""
    return port_number(container_port) or port_number(env_port)
