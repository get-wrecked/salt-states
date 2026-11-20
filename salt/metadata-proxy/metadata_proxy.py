#!/usr/bin/env python3

################################################
# File managed by salt state metadata-proxy    #
################################################

"""Per-user GCE metadata proxy.

Hands out tokens for a configured service account on each loopback port, so
that a local user whose metadata traffic iptables redirects to that port gets
credentials for that account only, never the VM's own identity. Tokens are
minted through the IAM Credentials API with the VM's identity, which the
proxy's own user reads from the real metadata server.

Only what application default credentials need is served: the service
account's token, email, scopes and identity, the project id and number, and
the instance zone and name. Everything else is 404, so instance attributes
never pass through.

The redirect decides which port a user's metadata traffic lands on, not who
may connect to a port: any local user can connect to a loopback port
directly. So each request is also checked against the uid that owns the
client end of the connection, read from /proc/net/tcp, and refused unless it
is the port's user. iptables rejects such connections too; this is the second
layer, so that a mistake in the rules or a port that moved between users
fails closed.
"""

import argparse
import base64
import collections
import datetime
import json
import logging
import pwd
import signal
import socket
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_CONFIG_PATH = "/etc/metadata-proxy.json"
DEFAULT_UPSTREAM = "http://169.254.169.254"
IAM_CREDENTIALS = "https://iamcredentials.googleapis.com/v1"
METADATA_PREFIX = "/computeMetadata/v1/"
DEFAULT_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)
# Marker in the config for "the project's default compute service account",
# resolved from the project number at first use.
DEFAULT_COMPUTE = "default-compute"
# Tokens are minted for this long and replaced this long before they expire.
TOKEN_LIFETIME = datetime.timedelta(hours=1)
TOKEN_REFRESH_MARGIN = datetime.timedelta(minutes=5)
# Distinct scope sets and audiences cached per identity. The caller chooses
# them, so the cache is bounded; past this the oldest entry goes.
MAX_CACHED_TOKENS = 64
UPSTREAM_TIMEOUT = 5
IAM_TIMEOUT = 15
# A client on an AF_INET6 socket reaching the IPv4 listener through a mapped
# address is listed in the second table, with ::ffff: in front of its address.
TCP_TABLES = ("/proc/net/tcp", "/proc/net/tcp6")

# Upstream paths passed through unchanged, cached forever since they never
# change for a running instance.
PASSTHROUGH_PATHS = (
    "project/project-id",
    "project/numeric-project-id",
    "instance/zone",
    "instance/name",
)

log = logging.getLogger("metadata-proxy")

Listener = collections.namedtuple("Listener", "port user service_account")
TcpSocket = collections.namedtuple("TcpSocket", "local remote state uid")
# The state column of a connected socket, as the kernel writes it
TCP_ESTABLISHED = "01"
METADATA_ADDRESS = ("169.254.169.254", 80)


def main():
    args = get_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    with open(args.config) as fh:
        listeners = parse_config(json.load(fh))
    upstream = Upstream(args.upstream)
    servers = [IdentityServer(args.bind, listener, upstream) for listener in listeners]
    serve_forever(servers)


def parse_config(config):
    listeners = []
    for entry in config["listeners"]:
        listener = Listener(
            port=int(entry["port"]),
            user=entry["user"],
            service_account=entry["service_account"],
        )
        if not 0 < listener.port < 65536:
            raise ValueError("listener port out of range: %r" % (listener.port,))
        if not listener.service_account:
            raise ValueError("listener for %s has no service account" % listener.user)
        listeners.append(listener)
    ports = [listener.port for listener in listeners]
    if len(set(ports)) != len(ports):
        raise ValueError("listener ports must be unique: %r" % (ports,))
    return listeners


class IdentityServer(ThreadingHTTPServer):
    """One listener: a port that serves one service account to one local user."""

    daemon_threads = True

    def __init__(self, bind, listener, upstream):
        super().__init__((bind, listener.port), Handler)
        self.listener = listener
        self.upstream = upstream
        self.identity = Identity(listener.service_account, upstream)

    def expected_uid(self):
        """The uid of the listener's user, or None if there is no such user.

        Looked up every time, so that a user recreated with another uid is
        served without a restart, as iptables picks up the new uid on the next
        rule load."""
        try:
            return user_uid(self.listener.user)
        except KeyError:
            log.error("no local user %s, refusing all requests", self.listener.user)
            return None


def serve_forever(servers):
    threads = []
    for server in servers:
        log.info(
            "serving %s on port %d for %s",
            server.listener.service_account,
            server.listener.port,
            server.listener.user,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)

    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    stop.wait()
    log.info("shutting down")
    for server in servers:
        server.shutdown()
        server.server_close()


class Handler(BaseHTTPRequestHandler):
    # The real metadata server identifies itself this way, and clients check
    # for it when detecting that they run on GCE.
    server_version = "Metadata Server for VM"
    protocol_version = "HTTP/1.1"
    # A connection that sends nothing for this long is closed, so that a
    # caller cannot hold threads open by never finishing a request
    timeout = 10

    def version_string(self):
        return self.server_version

    def do_GET(self):
        if not self.caller_is_listener_user():
            self.send_text("Not the user this port serves.\n", 403)
            return

        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)
        path = url.path
        if path == "/":
            self.send_text("computeMetadata/\n")
            return

        if self.headers.get("Metadata-Flavor") != "Google":
            self.send_text("Missing Metadata-Flavor:Google header.\n", 403)
            return

        if not path.startswith(METADATA_PREFIX):
            self.send_text("", 404)
            return

        try:
            self.route(path[len(METADATA_PREFIX) :], query)
        except UpstreamError as error:
            log.error("%s: %s", self.path, error)
            self.send_text("%s\n" % error, 502)

    def route(self, path, query):
        identity = self.server.identity
        if path in ("", "/"):
            self.send_text("instance/\nproject/\n")
        elif path in PASSTHROUGH_PATHS:
            self.send_text(self.server.upstream.get(path))
        elif path == "universe/universe-domain":
            self.send_text("googleapis.com")
        elif path == "instance/service-accounts/":
            if query.get("recursive", [""])[0].lower() == "true":
                info = service_account_info(identity.email())
                self.send_json({"default": info, identity.email(): info})
            else:
                self.send_text("default/\n%s/\n" % identity.email())
        elif path.startswith("instance/service-accounts/"):
            self.route_service_account(path[len("instance/service-accounts/") :], query)
        else:
            self.send_text("", 404)

    def route_service_account(self, path, query):
        identity = self.server.identity
        account, _, attribute = path.partition("/")
        if urllib.parse.unquote(account) not in ("default", identity.email()):
            self.send_text("", 404)
        elif attribute == "":
            if query.get("recursive", [""])[0].lower() == "true":
                self.send_json(service_account_info(identity.email()))
            else:
                self.send_text("aliases\nemail\nidentity\nscopes\ntoken\n")
        elif attribute == "aliases":
            self.send_text("default")
        elif attribute == "email":
            self.send_text(identity.email())
        elif attribute == "scopes":
            self.send_text("".join("%s\n" % scope for scope in DEFAULT_SCOPES))
        elif attribute == "token":
            scopes = parse_scopes(query.get("scopes", [""])[0])
            self.send_json(identity.access_token(scopes))
        elif attribute == "identity":
            audience = query.get("audience", [""])[0]
            if not audience:
                self.send_text("non-empty audience parameter required\n", 400)
                return
            include_email = query.get("format", [""])[0] == "full"
            self.send_text(identity.id_token(audience, include_email))
        else:
            self.send_text("", 404)

    def caller_is_listener_user(self):
        expected = self.server.expected_uid()
        actual = peer_uid(self.client_address, self.server.server_address)
        if expected is not None and actual == expected:
            return True
        log.warning(
            "refused %s on port %d for %s: client %s:%d is uid %s, not %s",
            self.path,
            self.server.listener.port,
            self.server.listener.user,
            self.client_address[0],
            self.client_address[1],
            actual,
            expected,
        )
        return False

    def send_json(self, data):
        self.send_text(json.dumps(data), content_type="application/json")

    def send_text(self, body, status=200, content_type="application/text"):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Metadata-Flavor", "Google")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        log.debug("%s %s", self.server.listener.user, format % args)


def service_account_info(email):
    return {"aliases": ["default"], "email": email, "scopes": list(DEFAULT_SCOPES)}


def parse_scopes(value):
    scopes = tuple(scope for scope in value.replace(",", " ").split() if scope)
    return scopes or DEFAULT_SCOPES


def peer_uid(client_address, server_address):
    """The uid owning the client end of a TCP connection from this host.

    The connection is to a loopback port, so the client's socket is in this
    host's TCP table, listed by its local address, which is what we see as
    the peer. A redirected connection keeps the client's source address (the
    instance's own) and its original destination, the metadata address; only
    the packets were rewritten. A direct connection has our own address as its
    destination. Both are established while we handle a request, which rules
    out an old socket in TIME_WAIT (listed as root's) or another connection
    that reused the port towards another destination. None if the socket is
    not found, or if more than one matches.
    """
    client = (client_address[0], client_address[1])
    server = (server_address[0], server_address[1])
    uids = {
        entry.uid
        for entry in read_tcp_table()
        if entry.local == client
        and entry.remote in (METADATA_ADDRESS, server)
        and entry.state == TCP_ESTABLISHED
    }
    if len(uids) != 1:
        return None
    return uids.pop()


def read_tcp_table():
    entries = []
    for path in TCP_TABLES:
        try:
            with open(path) as fh:
                lines = fh.read().splitlines()[1:]
        except OSError as error:
            log.error("cannot read %s: %s", path, error)
            continue
        entries.extend(parse_tcp_entry(line) for line in lines if line.strip())
    return entries


def parse_tcp_entry(line):
    # sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid ...
    fields = line.split()
    return TcpSocket(
        local=parse_tcp_address(fields[1]),
        remote=parse_tcp_address(fields[2]),
        state=fields[3],
        uid=int(fields[7]),
    )


def parse_tcp_address(value):
    """'0100007F:1FA4' -> ('127.0.0.1', 8100).

    The kernel writes each 32-bit word of the address in host byte order,
    little-endian on every machine we run: one word for IPv4, four for IPv6.
    An IPv4-mapped IPv6 address comes back as the IPv4 address it maps, which
    is how the IPv4 listener sees such a client."""
    address, port = value.split(":")
    raw = bytes.fromhex(address)
    words = [raw[i : i + 4][::-1] for i in range(0, len(raw), 4)]
    if len(words) == 1:
        host = socket.inet_ntoa(words[0])
    else:
        packed = b"".join(words)
        if packed.startswith(b"\0" * 10 + b"\xff\xff"):
            host = socket.inet_ntoa(packed[12:])
        else:
            host = socket.inet_ntop(socket.AF_INET6, packed)
    return host, int(port, 16)


def user_uid(name):
    return pwd.getpwnam(name).pw_uid


class Identity:
    """Tokens for one service account, cached until shortly before expiry."""

    def __init__(self, service_account, upstream):
        self.service_account = service_account
        self.upstream = upstream
        self.lock = threading.Lock()
        self.access_tokens = {}
        self.id_tokens = {}

    def email(self):
        if self.service_account == DEFAULT_COMPUTE:
            project_number = self.upstream.get("project/numeric-project-id")
            self.service_account = (
                "%s-compute@developer.gserviceaccount.com" % project_number
            )
        return self.service_account

    def access_token(self, scopes):
        with self.lock:
            cached = self.access_tokens.get(scopes)
            if cached is None or is_expiring(cached["expiry"]):
                cached = self.mint_access_token(scopes)
                cache_token(self.access_tokens, scopes, cached)
            return {
                "access_token": cached["token"],
                "expires_in": seconds_until(cached["expiry"]),
                "token_type": "Bearer",
            }

    def mint_access_token(self, scopes):
        response = self.upstream.generate(
            self.email(),
            "generateAccessToken",
            {"scope": list(scopes), "lifetime": "%ds" % TOKEN_LIFETIME.total_seconds()},
        )
        log.info(
            "minted access token for %s with scopes %s", self.email(), " ".join(scopes)
        )
        return {
            "token": response["accessToken"],
            "expiry": parse_expire_time(response["expireTime"]),
        }

    def id_token(self, audience, include_email):
        key = (audience, include_email)
        with self.lock:
            cached = self.id_tokens.get(key)
            if cached is None or is_expiring(cached["expiry"]):
                cached = self.mint_id_token(audience, include_email)
                cache_token(self.id_tokens, key, cached)
            return cached["token"]

    def mint_id_token(self, audience, include_email):
        response = self.upstream.generate(
            self.email(),
            "generateIdToken",
            {"audience": audience, "includeEmail": include_email},
        )
        log.info("minted id token for %s with audience %s", self.email(), audience)
        token = response["token"]
        return {"token": token, "expiry": jwt_expiry(token)}


def cache_token(cache, key, entry):
    """Store a minted token, dropping expired entries and then the oldest
    beyond MAX_CACHED_TOKENS. Dicts keep insertion order, so the first key is
    the oldest."""
    cache.pop(key, None)
    for expired in [k for k, v in cache.items() if is_expiring(v["expiry"])]:
        del cache[expired]
    while len(cache) >= MAX_CACHED_TOKENS:
        del cache[next(iter(cache))]
    cache[key] = entry


class Upstream:
    """The real metadata server, and the IAM Credentials API through its token."""

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.lock = threading.Lock()
        self.cache = {}
        self.vm_token = None

    def get(self, path):
        with self.lock:
            if path not in self.cache:
                self.cache[path] = self.fetch(path)
            return self.cache[path]

    def fetch(self, path):
        url = "%s%s%s" % (self.base_url, METADATA_PREFIX, path)
        return http_request(
            url, {"Metadata-Flavor": "Google"}, timeout=UPSTREAM_TIMEOUT
        )

    def token(self):
        """The VM's own access token, which authenticates the IAM Credentials calls."""
        with self.lock:
            if self.vm_token is None or is_expiring(self.vm_token["expiry"]):
                response = json.loads(
                    self.fetch("instance/service-accounts/default/token")
                )
                self.vm_token = {
                    "token": response["access_token"],
                    "expiry": now()
                    + datetime.timedelta(seconds=response["expires_in"]),
                }
            return self.vm_token["token"]

    def generate(self, service_account, method, body):
        url = "%s/projects/-/serviceAccounts/%s:%s" % (
            IAM_CREDENTIALS,
            urllib.parse.quote(service_account),
            method,
        )
        headers = {
            "Authorization": "Bearer %s" % self.token(),
            "Content-Type": "application/json",
        }
        response = http_request(
            url, headers, json.dumps(body).encode("utf-8"), IAM_TIMEOUT
        )
        return json.loads(response)


class UpstreamError(Exception):
    pass


def http_request(url, headers, data=None, timeout=UPSTREAM_TIMEOUT):
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        raise UpstreamError("%s returned %d: %s" % (url, error.code, body.strip()))
    except (urllib.error.URLError, OSError) as error:
        raise UpstreamError("%s failed: %s" % (url, error))


def parse_expire_time(value):
    # RFC 3339 with a Z suffix, as the IAM Credentials API writes it
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def jwt_expiry(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return datetime.datetime.fromtimestamp(claims["exp"], datetime.timezone.utc)


def is_expiring(expiry):
    return expiry - now() < TOKEN_REFRESH_MARGIN


def seconds_until(expiry):
    return max(0, int((expiry - now()).total_seconds()))


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def get_args():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument(
        "--upstream",
        default=DEFAULT_UPSTREAM,
        help="The real metadata server (default: %(default)s)",
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="The address the identity ports listen on (default: %(default)s)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Log every request"
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()
