import base64
import datetime
import io
import json
import os
import pwd
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from importlib.util import module_from_spec, spec_from_file_location

import pytest


def load_proxy():
    spec = spec_from_file_location(
        "metadata_proxy", os.path.join(os.path.dirname(__file__), "metadata_proxy.py")
    )
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


proxy = load_proxy()
# What the autouse fixture replaces, for the test over a real socket
read_real_tcp_table = proxy.read_tcp_table
real_user_uid = proxy.user_uid

SERVICE_ACCOUNT = "terraform@medal-test.iam.gserviceaccount.com"
UPSTREAM = "http://169.254.169.254"
METADATA = UPSTREAM + "/computeMetadata/v1/"
PROJECT_NUMBER = "123456789012"
# The connection the handler tests see: a terraform-owned client socket
CLIENT = ("10.0.0.5", 40000)
USERS = {"terraform": 998, "_apt": 42}


class FakeGoogle:
    """The real metadata server and the IAM Credentials API, as http_request sees them."""

    def __init__(self):
        self.calls = []
        self.vm_tokens_issued = 0
        self.minted = 0

    def __call__(self, url, headers, data=None, timeout=None):
        self.calls.append((url, headers, data))
        if url.startswith(METADATA):
            assert headers == {"Metadata-Flavor": "Google"}
            return self.metadata(url[len(METADATA) :])
        if url.startswith(proxy.IAM_CREDENTIALS):
            assert (
                headers["Authorization"]
                == "Bearer fake-vm-token-%d" % self.vm_tokens_issued
            )
            return self.iam(url[len(proxy.IAM_CREDENTIALS) :], json.loads(data))
        raise AssertionError("unexpected url %s" % url)

    def metadata(self, path):
        if path == "instance/service-accounts/default/token":
            self.vm_tokens_issued += 1
            return json.dumps(
                {
                    "access_token": "fake-vm-token-%d" % self.vm_tokens_issued,
                    "expires_in": 3599,
                    "token_type": "Bearer",
                }
            )
        values = {
            "project/project-id": "medal-test",
            "project/numeric-project-id": PROJECT_NUMBER,
            "instance/zone": "projects/%s/zones/us-east4-a" % PROJECT_NUMBER,
            "instance/name": "saltmaster",
            "instance/attributes/startup-script": "#!/bin/sh\necho secret",
        }
        return values[path]

    def iam(self, path, body):
        self.minted += 1
        account, _, method = path.rpartition(":")
        assert account.startswith("/projects/-/serviceAccounts/")
        email = urllib.parse.unquote(account[len("/projects/-/serviceAccounts/") :])
        if method == "generateAccessToken":
            assert body["lifetime"] == "3600s"
            expiry = proxy.now() + datetime.timedelta(hours=1)
            return json.dumps(
                {
                    "accessToken": "fake-sa-token-%d-%s"
                    % (self.minted, " ".join(body["scope"])),
                    "expireTime": expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            )
        if method == "generateIdToken":
            claims = {
                "aud": body["audience"],
                "exp": int((proxy.now() + datetime.timedelta(hours=1)).timestamp()),
                "iss": "https://accounts.google.com",
                "sub": "1234",
            }
            if body["includeEmail"]:
                claims["email"] = email
            return json.dumps({"token": "h.%s.s" % encode_jwt_part(claims)})
        raise AssertionError("unexpected IAM method %s" % method)


def encode_jwt_part(claims):
    return base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()


@pytest.fixture
def google(monkeypatch):
    fake = FakeGoogle()
    monkeypatch.setattr(proxy, "http_request", fake)
    return fake


@pytest.fixture(autouse=True)
def local_users(monkeypatch):
    """The host's users and TCP table: terraform owns the test client socket."""
    monkeypatch.setattr(proxy, "user_uid", lambda name: USERS[name])
    table = [proxy.TcpSocket(CLIENT, ("169.254.169.254", 80), "01", USERS["terraform"])]
    monkeypatch.setattr(proxy, "read_tcp_table", lambda: table)
    return table


@pytest.fixture
def server(google):
    return FakeServer(SERVICE_ACCOUNT)


class FakeServer:
    def __init__(self, service_account, user="terraform"):
        self.listener = proxy.Listener(8101, user, service_account)
        self.server_address = ("127.0.0.1", 8101)
        self.upstream = proxy.Upstream(UPSTREAM)
        self.identity = proxy.Identity(service_account, self.upstream)
        self.expected_uid = proxy.IdentityServer.expected_uid.__get__(self)


class FakeSocket:
    def __init__(self, request):
        self.reader = io.BytesIO(request)
        self.written = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        return self.reader

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        self.written.write(data)


def get(server, path, headers=None, flavor=True):
    """Run one GET through the handler without a socket. Returns (status, headers, body)."""
    if headers is None:
        headers = {}
    if flavor:
        headers["Metadata-Flavor"] = "Google"
    request = "GET %s HTTP/1.1\r\nHost: metadata\r\n" % path
    request += "".join("%s: %s\r\n" % item for item in headers.items())
    request += "\r\n"
    sock = FakeSocket(request.encode())
    proxy.Handler(sock, CLIENT, server)
    head, _, body = sock.written.getvalue().partition(b"\r\n\r\n")
    status_line, *header_lines = head.decode().split("\r\n")
    status = int(status_line.split()[1])
    response_headers = dict(line.split(": ", 1) for line in header_lines)
    return status, response_headers, body.decode()


def test_root_identifies_as_metadata_server_without_flavor(server):
    status, headers, body = get(server, "/", flavor=False)
    assert status == 200
    assert headers["Metadata-Flavor"] == "Google"
    assert headers["Server"] == "Metadata Server for VM"
    assert body == "computeMetadata/\n"


def test_flavor_header_required(server):
    status, _, body = get(
        server, "/computeMetadata/v1/project/project-id", flavor=False
    )
    assert status == 403
    assert "Metadata-Flavor" in body


def test_passthrough_paths(server, google):
    assert get(server, "/computeMetadata/v1/project/project-id")[2] == "medal-test"
    assert (
        get(server, "/computeMetadata/v1/project/numeric-project-id")[2]
        == PROJECT_NUMBER
    )
    assert get(server, "/computeMetadata/v1/instance/zone")[2].endswith("us-east4-a")
    assert get(server, "/computeMetadata/v1/instance/name")[2] == "saltmaster"
    # Cached after the first read
    calls = len(google.calls)
    get(server, "/computeMetadata/v1/project/project-id")
    assert len(google.calls) == calls


def test_instance_attributes_are_not_served(server, google):
    status, _, body = get(
        server, "/computeMetadata/v1/instance/attributes/startup-script"
    )
    assert status == 404
    assert "secret" not in body
    assert google.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "/computeMetadata/v1beta1/instance/service-accounts/default/token",
        "/computeMetadata/v1/instance/service-accounts/other@example.com/token",
        "/computeMetadata/v1/instance/service-accounts/default/unknown",
        "/computeMetadata/v1/instance/",
        "/computeMetadata/v1/instance/id",
        "/computeMetadata/v1/project/attributes/ssh-keys",
        "/other",
    ],
)
def test_unknown_paths_are_404(server, google, path):
    assert get(server, path)[0] == 404
    assert google.calls == []


def test_service_account_listing(server):
    assert get(server, "/computeMetadata/v1/")[2] == "instance/\nproject/\n"
    assert (
        get(server, "/computeMetadata/v1/instance/service-accounts/")[2]
        == "default/\n%s/\n" % SERVICE_ACCOUNT
    )
    listing = "aliases\nemail\nidentity\nscopes\ntoken\n"
    assert (
        get(server, "/computeMetadata/v1/instance/service-accounts/default/")[2]
        == listing
    )
    assert (
        get(
            server,
            "/computeMetadata/v1/instance/service-accounts/%s/" % SERVICE_ACCOUNT,
        )[2]
        == listing
    )
    assert get(server, "/computeMetadata/v1/instance/service-accounts/default/email")[
        2
    ] == (SERVICE_ACCOUNT)
    assert get(server, "/computeMetadata/v1/instance/service-accounts/default/aliases")[
        2
    ] == ("default")
    assert get(server, "/computeMetadata/v1/instance/service-accounts/default/scopes")[
        2
    ] == ("https://www.googleapis.com/auth/cloud-platform\n")


def test_service_account_listing_recursive(server):
    status, _, body = get(
        server, "/computeMetadata/v1/instance/service-accounts/?recursive=true"
    )
    assert status == 200
    info = {
        "aliases": ["default"],
        "email": SERVICE_ACCOUNT,
        "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
    }
    assert json.loads(body) == {"default": info, SERVICE_ACCOUNT: info}


def test_service_account_by_encoded_email(server):
    encoded = urllib.parse.quote(SERVICE_ACCOUNT)
    assert "%40" in encoded
    path = "/computeMetadata/v1/instance/service-accounts/%s/email" % encoded
    assert get(server, path) == get(
        server, "/computeMetadata/v1/instance/service-accounts/default/email"
    )


def test_service_account_recursive(server):
    status, headers, body = get(
        server, "/computeMetadata/v1/instance/service-accounts/default/?recursive=true"
    )
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body) == {
        "aliases": ["default"],
        "email": SERVICE_ACCOUNT,
        "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
    }


def test_access_token_is_minted_through_iam_credentials(server, google):
    status, headers, body = get(
        server, "/computeMetadata/v1/instance/service-accounts/default/token"
    )
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    token = json.loads(body)
    assert (
        token["access_token"]
        == "fake-sa-token-1-https://www.googleapis.com/auth/cloud-platform"
    )
    assert token["token_type"] == "Bearer"
    assert 3500 < token["expires_in"] <= 3600

    iam_url, _, request = google.calls[-1]
    assert iam_url == (
        "%s/projects/-/serviceAccounts/terraform%%40medal-test.iam.gserviceaccount.com"
        ":generateAccessToken" % proxy.IAM_CREDENTIALS
    )
    assert json.loads(request) == {
        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
        "lifetime": "3600s",
    }


def test_access_token_is_cached_until_near_expiry(server, google, monkeypatch):
    path = "/computeMetadata/v1/instance/service-accounts/default/token"
    first = json.loads(get(server, path)[2])
    second = json.loads(get(server, path)[2])
    assert first["access_token"] == second["access_token"]
    assert google.minted == 1

    real_now = proxy.now
    later = real_now() + datetime.timedelta(minutes=56)
    monkeypatch.setattr(proxy, "now", lambda: later)
    third = json.loads(get(server, path)[2])
    assert third["access_token"] != first["access_token"]
    assert google.minted == 2


def test_access_token_scopes_from_query(server, google):
    body = get(
        server,
        "/computeMetadata/v1/instance/service-accounts/default/token"
        "?scopes=https://www.googleapis.com/auth/devstorage.read_only,"
        "https://www.googleapis.com/auth/logging.write",
    )[2]
    assert json.loads(body)["access_token"] == (
        "fake-sa-token-1-https://www.googleapis.com/auth/devstorage.read_only"
        " https://www.googleapis.com/auth/logging.write"
    )
    assert google.minted == 1
    # A different scope set is a different token
    get(server, "/computeMetadata/v1/instance/service-accounts/default/token")
    assert google.minted == 2


def test_vm_token_is_reused_across_mints(server, google):
    get(server, "/computeMetadata/v1/instance/service-accounts/default/token")
    get(
        server,
        "/computeMetadata/v1/instance/service-accounts/default/identity?audience=a",
    )
    assert google.vm_tokens_issued == 1
    assert google.minted == 2


def test_id_token(server, google):
    path = "/computeMetadata/v1/instance/service-accounts/default/identity?audience=sts.amazonaws.com"
    status, _, body = get(server, path)
    assert status == 200
    claims = json.loads(base64.urlsafe_b64decode(body.split(".")[1] + "=="))
    assert claims["aud"] == "sts.amazonaws.com"
    assert "email" not in claims
    assert json.loads(google.calls[-1][2]) == {
        "audience": "sts.amazonaws.com",
        "includeEmail": False,
    }

    # Cached per audience and format
    assert get(server, path)[2] == body
    assert google.minted == 1
    full = get(server, path + "&format=full")[2]
    assert json.loads(base64.urlsafe_b64decode(full.split(".")[1] + "=="))["email"] == (
        SERVICE_ACCOUNT
    )
    assert google.minted == 2


def test_id_token_requires_audience(server, google):
    status, _, _ = get(
        server, "/computeMetadata/v1/instance/service-accounts/default/identity"
    )
    assert status == 400
    assert google.calls == []


def test_default_compute_service_account_is_resolved_from_project_number(google):
    server = FakeServer(proxy.DEFAULT_COMPUTE)
    email = "%s-compute@developer.gserviceaccount.com" % PROJECT_NUMBER
    assert (
        get(server, "/computeMetadata/v1/instance/service-accounts/default/email")[2]
        == email
    )
    assert (
        get(server, "/computeMetadata/v1/instance/service-accounts/")[2]
        == "default/\n%s/\n" % email
    )
    get(server, "/computeMetadata/v1/instance/service-accounts/default/token")
    iam_url = google.calls[-1][0]
    assert iam_url == (
        "%s/projects/-/serviceAccounts/%s-compute%%40developer.gserviceaccount.com"
        ":generateAccessToken" % (proxy.IAM_CREDENTIALS, PROJECT_NUMBER)
    )


def test_upstream_failure_is_a_502_without_a_token(server, monkeypatch):
    def failing(url, headers, data=None, timeout=None):
        raise proxy.UpstreamError("%s returned 403: permission denied" % url)

    monkeypatch.setattr(proxy, "http_request", failing)
    status, _, body = get(
        server, "/computeMetadata/v1/instance/service-accounts/default/token"
    )
    assert status == 502
    assert "permission denied" in body


def test_parse_config():
    listeners = proxy.parse_config(
        {
            "listeners": [
                {"port": 8101, "user": "terraform", "service_account": SERVICE_ACCOUNT},
                {"port": "8102", "user": "_apt", "service_account": "default-compute"},
            ]
        }
    )
    assert listeners == [
        proxy.Listener(8101, "terraform", SERVICE_ACCOUNT),
        proxy.Listener(8102, "_apt", "default-compute"),
    ]


@pytest.mark.parametrize(
    "listeners",
    [
        [
            {"port": 8101, "user": "a", "service_account": SERVICE_ACCOUNT},
            {"port": 8101, "user": "b", "service_account": SERVICE_ACCOUNT},
        ],
        [{"port": 0, "user": "a", "service_account": SERVICE_ACCOUNT}],
        [{"port": 8101, "user": "a", "service_account": ""}],
    ],
)
def test_parse_config_rejects_bad_listeners(listeners):
    with pytest.raises(ValueError):
        proxy.parse_config({"listeners": listeners})


def test_parse_scopes():
    assert proxy.parse_scopes("") == proxy.DEFAULT_SCOPES
    assert proxy.parse_scopes("a,b") == ("a", "b")
    assert proxy.parse_scopes("a b") == ("a", "b")


def test_refuses_another_users_connection(server, google, local_users):
    """The port serves terraform; a client socket owned by _apt gets nothing."""
    local_users[0] = proxy.TcpSocket(CLIENT, ("127.0.0.1", 8101), "01", USERS["_apt"])
    status, _, body = get(
        server, "/computeMetadata/v1/instance/service-accounts/default/token"
    )
    assert status == 403
    assert "Not the user" in body
    assert google.calls == []
    # The ping without the flavor header is refused the same way
    assert get(server, "/", flavor=False)[0] == 403


def test_refuses_connection_not_in_tcp_table(server, google, local_users):
    local_users.clear()
    assert get(server, "/computeMetadata/v1/project/project-id")[0] == 403
    assert google.calls == []


def test_refuses_ambiguous_client_address(server, google, local_users):
    local_users.append(
        proxy.TcpSocket(CLIENT, ("127.0.0.1", 8101), "01", USERS["_apt"])
    )
    assert get(server, "/computeMetadata/v1/project/project-id")[0] == 403
    assert google.calls == []


def test_ignores_other_connections_from_the_same_port(server, google, local_users):
    """Only an established socket to us or to the metadata address counts: an
    old one in TIME_WAIT (listed as root's) or a reused port towards another
    destination does not make the lookup ambiguous."""
    local_users.append(proxy.TcpSocket(CLIENT, ("127.0.0.1", 8101), "06", 0))
    local_users.append(proxy.TcpSocket(CLIENT, ("10.0.0.9", 443), "01", USERS["_apt"]))
    assert get(server, "/computeMetadata/v1/project/project-id")[0] == 200
    # A direct connection to our own address counts too
    local_users[0] = proxy.TcpSocket(
        CLIENT, ("127.0.0.1", 8101), "01", USERS["terraform"]
    )
    assert get(server, "/computeMetadata/v1/project/project-id")[0] == 200
    # But not one that is no longer established
    local_users[0] = proxy.TcpSocket(
        CLIENT, ("127.0.0.1", 8101), "08", USERS["terraform"]
    )
    assert get(server, "/computeMetadata/v1/project/project-id")[0] == 403


def test_refuses_everything_when_listener_user_is_missing(google):
    server = FakeServer(SERVICE_ACCOUNT, user="nobody-here")
    with pytest.raises(KeyError):
        proxy.user_uid("nobody-here")
    assert get(server, "/computeMetadata/v1/project/project-id")[0] == 403
    assert google.calls == []


def test_parse_tcp_table_entry():
    line = (
        "   3: 0500000A:9C40 FEA9FEA9:0050 01 00000000:00000000 00:00000000"
        " 00000000   998        0 123456 1 0000000000000000 20 4 30 10 -1"
    )
    assert proxy.parse_tcp_entry(line) == proxy.TcpSocket(
        ("10.0.0.5", 40000), ("169.254.169.254", 80), "01", 998
    )
    assert proxy.parse_tcp_address("0100007F:1FA4") == ("127.0.0.1", 8100)


def test_parse_tcp6_table_entry():
    # A client on an AF_INET6 socket, ::ffff:127.0.0.1:40000 -> ::ffff:127.0.0.1:8100
    line = (
        "   1: 0000000000000000FFFF00000100007F:9C40"
        " 0000000000000000FFFF00000100007F:1FA4 01 00000000:00000000 00:00000000"
        " 00000000   998        0 123456 1 0000000000000000 20 4 30 10 -1"
    )
    assert proxy.parse_tcp_entry(line) == proxy.TcpSocket(
        ("127.0.0.1", 40000), ("127.0.0.1", 8100), "01", 998
    )
    # A real IPv6 address stays one: fd20:ce::254, word by word little-endian
    assert proxy.parse_tcp_address("CE0020FD000000000000000054020000:0050") == (
        "fd20:ce::254",
        80,
    )


def test_reads_both_tcp_tables(monkeypatch, tmp_path):
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    entry = " %s 01 00000000:00000000 00:00000000 00000000 %d 0 1 1 0000000000000000 20 4 30 10 -1\n"
    (tmp_path / "tcp").write_text(
        header + entry % ("0: 0500000A:9C40 FEA9FEA9:0050", 998)
    )
    (tmp_path / "tcp6").write_text(
        header
        + entry
        % (
            "0: 0000000000000000FFFF00000100007F:9C41 0000000000000000FFFF00000100007F:1FA4",
            42,
        )
    )
    monkeypatch.setattr(
        proxy,
        "TCP_TABLES",
        (str(tmp_path / "tcp"), str(tmp_path / "tcp6"), str(tmp_path / "missing")),
    )
    assert read_real_tcp_table() == [
        proxy.TcpSocket(("10.0.0.5", 40000), ("169.254.169.254", 80), "01", 998),
        proxy.TcpSocket(("127.0.0.1", 40001), ("127.0.0.1", 8100), "01", 42),
    ]


def test_token_cache_is_bounded(server, google, monkeypatch):
    monkeypatch.setattr(proxy, "MAX_CACHED_TOKENS", 3)
    path = "/computeMetadata/v1/instance/service-accounts/default/identity?audience="
    for audience in "abcd":
        get(server, path + audience)
    assert list(server.identity.id_tokens) == [
        ("b", False),
        ("c", False),
        ("d", False),
    ]
    # Expired entries go first, whatever their age
    server.identity.id_tokens[("c", False)]["expiry"] = proxy.now()
    get(server, path + "e")
    assert list(server.identity.id_tokens) == [("b", False), ("d", False), ("e", False)]
    assert google.minted == 5


def loopback_available():
    """The agent sandbox cannot connect to its own loopback ports."""
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client = socket.socket()
        client.settimeout(1)
        try:
            client.connect(listener.getsockname())
        finally:
            client.close()
    except OSError:
        return False
    finally:
        listener.close()
    return True


@pytest.mark.skipif(not loopback_available(), reason="no loopback connections here")
def test_serves_over_http(google, monkeypatch):
    """A client in this process is us, found in the real TCP table."""
    monkeypatch.setattr(proxy, "read_tcp_table", read_real_tcp_table)
    monkeypatch.setattr(proxy, "user_uid", real_user_uid)
    me = pwd.getpwuid(os.getuid()).pw_name
    listener = proxy.Listener(0, me, SERVICE_ACCOUNT)
    server = proxy.IdentityServer("127.0.0.1", listener, proxy.Upstream(UPSTREAM))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = "http://127.0.0.1:%d" % server.server_address[1]

        with urllib.request.urlopen(base + "/") as response:
            assert response.headers["Metadata-Flavor"] == "Google"
            assert response.read() == b"computeMetadata/\n"

        request = urllib.request.Request(
            base + "/computeMetadata/v1/instance/service-accounts/default/token",
            headers={"Metadata-Flavor": "Google"},
        )
        with urllib.request.urlopen(request) as response:
            token = json.loads(response.read())
        assert token["access_token"].startswith("fake-sa-token-1-")

        request = urllib.request.Request(
            base + "/computeMetadata/v1/instance/attributes/startup-script",
            headers={"Metadata-Flavor": "Google"},
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 404
    finally:
        server.shutdown()
        server.server_close()
