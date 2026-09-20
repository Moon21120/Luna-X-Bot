import os
import json
import time
import secrets
import hashlib
import base64
import threading
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer


# ============================================================
# CONFIG
# ============================================================

LUNA_API_URL = "https://lunadeveloperportal.onrender.com/v1/chat"

LUNA_API_KEY = os.environ.get("LUNA_API_KEY")

X_CLIENT_ID = os.environ.get("X_CLIENT_ID")
X_CLIENT_SECRET = os.environ.get("X_CLIENT_SECRET")

# After X gives you a refresh token, put it in Render as:
# X_REFRESH_TOKEN = <your refresh token>
X_REFRESH_TOKEN = os.environ.get("X_REFRESH_TOKEN")

# Must exactly match the callback URL configured in X:
# https://luna-x-bot.onrender.com/callback
X_REDIRECT_URI = os.environ.get("X_REDIRECT_URI")

PORT = int(os.environ.get("PORT", "10000"))

# How often Luna checks for new mentions.
CHECK_INTERVAL = 30


# ============================================================
# STATE
# ============================================================

access_token = None
refresh_token = X_REFRESH_TOKEN
token_expires_at = 0

oauth_state = None
oauth_verifier = None

last_mention_id = None
luna_user_id = None
luna_username = None

running = True


# ============================================================
# BASIC HTTP HELPERS
# ============================================================

def json_request(url, method="GET", headers=None, data=None):
    if headers is None:
        headers = {}

    body = None

    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")

            if not raw:
                return {}

            return json.loads(raw)

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")

        print(
            f"[HTTP ERROR] {e.code} {url}\n"
            f"{error_body}",
            flush=True
        )

        raise

    except Exception as e:
        print(
            f"[REQUEST ERROR] {url}: {e}",
            flush=True
        )

        raise


def form_request(url, data, headers=None):
    if headers is None:
        headers = {}

    encoded = urllib.parse.urlencode(data).encode("utf-8")

    headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(
        url,
        data=encoded,
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")

            if not raw:
                return {}

            return json.loads(raw)

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")

        print(
            f"[HTTP ERROR] {e.code} {url}\n"
            f"{error_body}",
            flush=True
        )

        raise


# ============================================================
# PKCE
# ============================================================

def base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_pkce():
    verifier = base64url(secrets.token_bytes(32))

    challenge_bytes = hashlib.sha256(
        verifier.encode("ascii")
    ).digest()

    challenge = base64url(challenge_bytes)

    return verifier, challenge


# ============================================================
# X OAUTH
# ============================================================

def authorization_url():
    global oauth_state
    global oauth_verifier

    oauth_state = secrets.token_urlsafe(32)

    oauth_verifier, challenge = create_pkce()

    params = {
        "response_type": "code",
        "client_id": X_CLIENT_ID,
        "redirect_uri": X_REDIRECT_URI,

        # offline.access is IMPORTANT because it allows X
        # to return a refresh token.
        "scope": "tweet.read tweet.write users.read offline.access",

        "state": oauth_state,
        "code_challenge": challenge,
        "code_challenge_method": "S256"
    }

    return (
        "https://twitter.com/i/oauth2/authorize?"
        + urllib.parse.urlencode(params)
    )


# ============================================================
# TOKEN MANAGEMENT
# ============================================================

def exchange_code(code):
    global access_token
    global refresh_token
    global token_expires_at

    print(
        "[OAUTH] Exchanging authorization code...",
        flush=True
    )

    credentials = base64.b64encode(
        f"{X_CLIENT_ID}:{X_CLIENT_SECRET}".encode()
    ).decode()

    headers = {
        "Authorization": f"Basic {credentials}"
    }

    data = {
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": X_REDIRECT_URI,
        "code_verifier": oauth_verifier
    }

    result = form_request(
        "https://api.x.com/2/oauth2/token",
        data,
        headers
    )

    # --------------------------------------------------------
    # ACCESS TOKEN
    # --------------------------------------------------------

    access_token = result.get("access_token")

    if not access_token:
        raise RuntimeError(
            "X did not return an access token."
        )

    # --------------------------------------------------------
    # REFRESH TOKEN
    # --------------------------------------------------------

    returned_refresh_token = result.get("refresh_token")

    if returned_refresh_token:
        refresh_token = returned_refresh_token

        print(
            "[OAUTH] Refresh token received: YES",
            flush=True
        )

        print()
        print("=" * 60)
        print("IMPORTANT - X REFRESH TOKEN")
        print("=" * 60)
        print(refresh_token)
        print("=" * 60)
        print(
            "Copy the token above and create this Render variable:"
        )
        print()
        print("X_REFRESH_TOKEN")
        print("=" * 60)
        print()
        print(
            "SECURITY: Do NOT share this token with anyone.",
            flush=True
        )

    else:
        print(
            "[OAUTH] Refresh token received: NO",
            flush=True
        )

        print(
            "[OAUTH] X returned an access token, but no refresh token.",
            flush=True
        )

        print(
            "[OAUTH] Make sure offline.access is being requested "
            "and authorize Luna again.",
            flush=True
        )

    # --------------------------------------------------------
    # EXPIRATION
    # --------------------------------------------------------

    expires_in = result.get("expires_in", 7200)

    token_expires_at = time.time() + expires_in

    print(
        f"[OAUTH] Access token received. "
        f"Expires in approximately {expires_in} seconds.",
        flush=True
    )

    print(
        "[OAUTH] Authorization successful.",
        flush=True
    )

    return bool(returned_refresh_token)


def refresh_access_token():
    global access_token
    global refresh_token
    global token_expires_at

    if not refresh_token:
        print(
            "[OAUTH] No X_REFRESH_TOKEN is configured.",
            flush=True
        )

        return False

    print(
        "[OAUTH] Refreshing X access token...",
        flush=True
    )

    credentials = base64.b64encode(
        f"{X_CLIENT_ID}:{X_CLIENT_SECRET}".encode()
    ).decode()

    headers = {
        "Authorization": f"Basic {credentials}"
    }

    data = {
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }

    try:
        result = form_request(
            "https://api.x.com/2/oauth2/token",
            data,
            headers
        )

        access_token = result.get("access_token")

        if not access_token:
            raise RuntimeError(
                "X did not return a new access token."
            )

        # X can rotate refresh tokens.
        new_refresh_token = result.get("refresh_token")

        if new_refresh_token:
            refresh_token = new_refresh_token

            print()
            print("=" * 60)
            print("[OAUTH] X ROTATED THE REFRESH TOKEN")
            print("=" * 60)
            print(refresh_token)
            print("=" * 60)
            print(
                "Update X_REFRESH_TOKEN in Render with "
                "the new token above."
            )
            print("=" * 60)
            print()

        expires_in = result.get("expires_in", 7200)

        token_expires_at = time.time() + expires_in

        print(
            "[OAUTH] Token refreshed successfully.",
            flush=True
        )

        return True

    except Exception as e:
        print(
            f"[OAUTH] Refresh failed: {e}",
            flush=True
        )

        return False


def ensure_access_token():
    global access_token

    # Current token is still valid.
    if access_token and time.time() < token_expires_at - 120:
        return True

    # Try the refresh token.
    if refresh_token:
        return refresh_access_token()

    return False


# ============================================================
# X API
# ============================================================

def x_get(url, params=None):
    if not ensure_access_token():
        raise RuntimeError(
            "Luna is not authorized with X yet."
        )

    if params:
        url += "?" + urllib.parse.urlencode(params)

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    try:
        return json_request(
            url,
            method="GET",
            headers=headers
        )

    except urllib.error.HTTPError as e:
        if e.code == 401 and refresh_access_token():
            headers = {
                "Authorization": f"Bearer {access_token}"
            }

            return json_request(
                url,
                method="GET",
                headers=headers
            )

        raise


def x_post(url, data):
    if not ensure_access_token():
        raise RuntimeError(
            "Luna is not authorized with X yet."
        )

    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    try:
        return json_request(
            url,
            method="POST",
            headers=headers,
            data=data
        )

    except urllib.error.HTTPError as e:
        if e.code == 401 and refresh_access_token():
            headers = {
                "Authorization": f"Bearer {access_token}"
            }

            return json_request(
                url,
                method="POST",
                headers=headers,
                data=data
            )

        raise


def get_luna_account():
    global luna_user_id
    global luna_username

    result = x_get(
        "https://api.x.com/2/users/me"
    )

    user = result["data"]

    luna_user_id = user["id"]
    luna_username = user["username"]

    print(
        f"[X] Connected as @{luna_username} "
        f"(ID: {luna_user_id})",
        flush=True
    )


# ============================================================
# MENTIONS
# ============================================================

def get_mentions():
    params = {
        "max_results": 10,
        "tweet.fields": "author_id,created_at",
        "expansions": "author_id",
        "user.fields": "username"
    }

    if last_mention_id:
        params["since_id"] = last_mention_id

    return x_get(
        f"https://api.x.com/2/users/"
        f"{luna_user_id}/mentions",
        params
    )


def reply_to_tweet(tweet_id, text):
    # Keep Luna's reply safely within X's character limit.
    if len(text) > 275:
        text = text[:272] + "..."

    data = {
        "text": text,
        "reply": {
            "in_reply_to_tweet_id": tweet_id
        }
    }

    result = x_post(
        "https://api.x.com/2/tweets",
        data
    )

    print(
        f"[X] Replied to {tweet_id}",
        flush=True
    )

    return result


# ============================================================
# LUNA API
# ============================================================

def ask_luna(message):
    print(
        f"[LUNA] Sending: {message}",
        flush=True
    )

    headers = {
        "Authorization": f"Bearer {LUNA_API_KEY}"
    }

    data = {
        "message": message
    }

    result = json_request(
        LUNA_API_URL,
        method="POST",
        headers=headers,
        data=data
    )

    response = result.get("response")

    if not response:
        raise RuntimeError(
            "Luna API returned no 'response' field."
        )

    return response


# ============================================================
# MENTION PROCESSING
# ============================================================

def clean_mention(text):
    if not text:
        return ""

    if luna_username:
        text = text.replace(
            f"@{luna_username}",
            ""
        )

        text = text.replace(
            f"@{luna_username.lower()}",
            ""
        )

    return text.strip()


def process_mentions():
    global last_mention_id

    try:
        result = get_mentions()

        tweets = result.get("data", [])

        if not tweets:
            return

        # X normally returns newest first.
        tweets = list(reversed(tweets))

        for tweet in tweets:
            tweet_id = tweet["id"]

            if last_mention_id:
                try:
                    if int(tweet_id) <= int(last_mention_id):
                        continue

                except Exception:
                    pass

            text = tweet.get("text", "")

            message = clean_mention(text)

            if not message:
                message = (
                    "Someone mentioned you without a message."
                )

            print()
            print(
                f"[MENTION] @{luna_username}: "
                f"{message}",
                flush=True
            )

            try:
                response = ask_luna(message)

                reply_to_tweet(
                    tweet_id,
                    response
                )

            except Exception as e:
                print(
                    f"[ERROR] Failed processing "
                    f"{tweet_id}: {e}",
                    flush=True
                )

            last_mention_id = tweet_id

    except Exception as e:
        print(
            f"[MENTIONS] {e}",
            flush=True
        )


# ============================================================
# WEB SERVER / OAUTH CALLBACK
# ============================================================

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Keep Render logs cleaner.
        return

    def send_page(self, status, html):
        body = html.encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.end_headers()

        self.wfile.write(body)

    def do_GET(self):

        parsed = urllib.parse.urlparse(
            self.path
        )

        path = parsed.path

        query = urllib.parse.parse_qs(
            parsed.query
        )

        # ----------------------------------------------------
        # HOME
        # ----------------------------------------------------

        if path == "/":

            if access_token:
                status = "Connected to X"
            elif refresh_token:
                status = "Refresh token configured"
            else:
                status = "Waiting for X authorization"

            self.send_page(
                200,
                f"""
                <html>
                <head>
                    <title>Luna X Bot</title>
                </head>

                <body>
                    <h1>Luna X Bot</h1>

                    <p>Status: {status}</p>

                    <p>
                        <a href="/auth">
                            Connect Luna to X
                        </a>
                    </p>
                </body>
                </html>
                """
            )

            return

        # ----------------------------------------------------
        # START OAUTH
        # ----------------------------------------------------

        if path == "/auth":

            if not X_CLIENT_ID:
                self.send_page(
                    500,
                    "<h1>X_CLIENT_ID is missing.</h1>"
                )
                return

            if not X_CLIENT_SECRET:
                self.send_page(
                    500,
                    "<h1>X_CLIENT_SECRET is missing.</h1>"
                )
                return

            if not X_REDIRECT_URI:
                self.send_page(
                    500,
                    "<h1>X_REDIRECT_URI is missing.</h1>"
                )
                return

            url = authorization_url()

            self.send_response(302)

            self.send_header(
                "Location",
                url
            )

            self.end_headers()

            return

        # ----------------------------------------------------
        # OAUTH CALLBACK
        # ----------------------------------------------------

        if path == "/callback":

            error = query.get(
                "error",
                [None]
            )[0]

            if error:

                self.send_page(
                    400,
                    f"""
                    <h1>Authorization failed</h1>
                    <p>{error}</p>
                    """
                )

                return

            returned_state = query.get(
                "state",
                [None]
            )[0]

            code = query.get(
                "code",
                [None]
            )[0]

            if not returned_state or not code:

                self.send_page(
                    400,
                    "<h1>Missing OAuth response.</h1>"
                )

                return

            if returned_state != oauth_state:

                self.send_page(
                    400,
                    "<h1>Invalid OAuth state.</h1>"
                )

                return

            try:

                got_refresh_token = exchange_code(code)

                get_luna_account()

                if got_refresh_token:

                    refresh_message = """
                    <p>
                        <strong>✓ Refresh token received!</strong>
                    </p>

                    <p>
                        Open your Render logs and copy the
                        refresh token into:
                    </p>

                    <p>
                        <strong>X_REFRESH_TOKEN</strong>
                    </p>
                    """

                else:

                    refresh_message = """
                    <p>
                        <strong>
                            ⚠ X did NOT return a refresh token.
                        </strong>
                    </p>

                    <p>
                        The authorization itself worked, but
                        Luna needs a refresh token to stay
                        connected after the access token expires.
                    </p>

                    <p>
                        Check the Render logs for:
                        <br>
                        <strong>
                            [OAUTH] Refresh token received: NO
                        </strong>
                    </p>

                    <p>
                        Make sure the authorization request includes
                        <strong>offline.access</strong>, then
                        authorize Luna again.
                    </p>
                    """

                self.send_page(
                    200,
                    f"""
                    <html>

                    <head>
                        <title>Luna Connected</title>
                    </head>

                    <body>

                        <h1>✓ Luna is connected!</h1>

                        <p>
                            Connected as
                            <strong>
                                @{luna_username}
                            </strong>
                        </p>

                        <p>
                            Luna can now monitor mentions.
                        </p>

                        {refresh_message}

                    </body>

                    </html>
                    """
                )

            except Exception as e:

                self.send_page(
                    500,
                    f"""
                    <h1>Authorization error</h1>

                    <pre>{e}</pre>
                    """
                )

            return

        # ----------------------------------------------------
        # NOT FOUND
        # ----------------------------------------------------

        self.send_page(
            404,
            "<h1>Not found</h1>"
        )


# ============================================================
# SERVER
# ============================================================

def start_web_server():

    server = HTTPServer(
        ("0.0.0.0", PORT),
        Handler
    )

    print(
        f"[WEB] Luna X OAuth server running "
        f"on port {PORT}",
        flush=True
    )

    server.serve_forever()


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60, flush=True)
    print("LUNA X BOT", flush=True)
    print("=" * 60, flush=True)

    if not LUNA_API_KEY:
        print(
            "ERROR: LUNA_API_KEY is missing.",
            flush=True
        )
        return

    if not X_CLIENT_ID:
        print(
            "ERROR: X_CLIENT_ID is missing.",
            flush=True
        )
        return

    if not X_CLIENT_SECRET:
        print(
            "ERROR: X_CLIENT_SECRET is missing.",
            flush=True
        )
        return

    if not X_REDIRECT_URI:
        print(
            "ERROR: X_REDIRECT_URI is missing.",
            flush=True
        )
        return

    # --------------------------------------------------------
    # START WEB SERVER
    # --------------------------------------------------------

    web_thread = threading.Thread(
        target=start_web_server,
        daemon=True
    )

    web_thread.start()

    print()
    print(
        "[WEB] Open your Render service URL",
        flush=True
    )

    print(
        "[WEB] Add /auth to authorize Luna with X.",
        flush=True
    )

    print()

    # --------------------------------------------------------
    # EXISTING REFRESH TOKEN
    # --------------------------------------------------------

    if refresh_token:

        print(
            "[X] X_REFRESH_TOKEN is configured.",
            flush=True
        )

        try:
            get_luna_account()

        except Exception as e:

            print(
                f"[X] Existing authorization failed: {e}",
                flush=True
            )

            print(
                "[X] Visit /auth to authorize again.",
                flush=True
            )

    else:

        print(
            "[X] No X_REFRESH_TOKEN configured yet.",
            flush=True
        )

        print(
            "[X] Visit /auth to connect Luna to X.",
            flush=True
        )

    print()

    # --------------------------------------------------------
    # MAIN MENTION LOOP
    # --------------------------------------------------------

    while running:

        if access_token:

            process_mentions()

        else:

            # If a refresh token exists, try connecting.
            if refresh_token:
                try:
                    get_luna_account()
                except Exception as e:
                    print(
                        f"[X] Waiting for authorization: {e}",
                        flush=True
                    )
            else:
                print(
                    "[X] Waiting for X authorization...",
                    flush=True
                )

        time.sleep(CHECK_INTERVAL)


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
