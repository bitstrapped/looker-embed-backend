from flask import Flask, jsonify, request
from flask_cors import CORS
import hmac
import hashlib
import base64
import json
import time
import binascii
import os
from dotenv import load_dotenv  # Import load_dotenv to load environment variables
from urllib.parse import quote_plus
import uuid

load_dotenv()

app = Flask(__name__)
CORS(app)

# Get Looker credentials and user info from environment variables
LOOKER_HOST = os.getenv("LOOKER_HOST")
LOOKER_EMBED_SECRET = os.getenv("LOOKER_EMBED_SECRET")
LOOKER_DASHBOARD_PATH = os.getenv("LOOKER_DASHBOARD_PATH")
LOOKER_EXPLORE_PATH = os.getenv("LOOKER_EXPLORE_PATH")

def generate_user_id():
    # Generate a random UUID
    user_id = uuid.uuid4()
    return str(user_id)

def to_ascii(s):
    if isinstance(s, str):
        return s
    elif isinstance(s, bytes):
        return "".join(map(chr, map(ord, s.decode(encoding="UTF-8"))))
    return s


class Looker:
    def __init__(self, host, secret):
        self.secret = secret
        self.host = host


class User:
    def __init__(
        self,
        id=id,
        first_name=None,
        last_name=None,
        permissions=[],
        models=[],
        group_ids=[],
        external_group_id=None,
        user_attributes={},
        access_filters={},
    ):
        self.external_user_id = json.dumps(id)
        self.first_name = json.dumps(first_name)
        self.last_name = json.dumps(last_name)
        self.permissions = json.dumps(permissions)
        self.models = json.dumps(models)
        self.access_filters = json.dumps(access_filters)
        self.user_attributes = json.dumps(user_attributes)
        self.group_ids = json.dumps(group_ids)
        self.external_group_id = json.dumps(external_group_id)


class URL:
    def __init__(
        self, looker, user, session_length, embed_url, force_logout_login=False
    ):
        self.looker = looker
        self.user = user
        self.path = "/login/embed/" + quote_plus(embed_url)
        self.session_length = json.dumps(session_length)
        self.force_logout_login = json.dumps(force_logout_login)

    def set_time(self):
        self.time = json.dumps(int(time.time()))

    def set_nonce(self):
        self.nonce = json.dumps(to_ascii(binascii.hexlify(os.urandom(16))))

    def sign(self):
        # Do not change the order of these
        string_to_sign = "\n".join(
            [
                self.looker.host,
                self.path,
                self.nonce,
                self.time,
                self.session_length,
                self.user.external_user_id,
                self.user.permissions,
                self.user.models,
                self.user.group_ids,
                self.user.external_group_id,
                self.user.user_attributes,
                self.user.access_filters,
            ]
        )

        signer = hmac.new(
            bytearray(self.looker.secret, "UTF-8"),
            string_to_sign.encode("UTF-8"),
            hashlib.sha1,
        )
        self.signature = base64.b64encode(signer.digest()).decode("utf-8")

    def to_string(self):
        self.set_time()
        self.set_nonce()
        self.sign()

        params = {
            "nonce": self.nonce,
            "time": self.time,
            "session_length": self.session_length,
            "external_user_id": self.user.external_user_id,
            "permissions": self.user.permissions,
            "models": self.user.models,
            "group_ids": self.user.group_ids,
            "external_group_id": self.user.external_group_id,
            "user_attributes": self.user.user_attributes,
            "access_filters": self.user.access_filters,
            "signature": self.signature,
            "first_name": self.user.first_name,
            "last_name": self.user.last_name,
            "force_logout_login": self.force_logout_login,
        }

        query_string = "&".join(
            ["%s=%s" % (key, quote_plus(val)) for key, val in params.items()]
        )

        return "%s%s?%s" % (self.looker.host, self.path, query_string)


@app.route("/get_embed_url", methods=["GET"])
def get_embed_url():
    # Replace these with your dynamic values
    embed_type = request.args.get("type", "dashboard")
    user_id = request.args.get("user_id", generate_user_id())
    first_name = request.args.get("first_name", "First Name")
    last_name = request.args.get("last_name", "Last Name")
    permissions = request.args.get(
        "permissions", '["access_data","see_looks","explore", "see_user_dashboards","see_lookml_dashboards"]'
    )
    models = request.args.get("models", '["returnalyze"]')
    group_ids = request.args.get("group_ids", "[]")
    external_group_id = request.args.get("external_group_id", "")
    user_attributes = request.args.get("user_attributes", "{}")
    access_filters = request.args.get("access_filters", "{}")
    session_length = 3600

    if embed_type == "explore":
        embed_url = LOOKER_EXPLORE_PATH
    else:  # Default to dashboard
        embed_url = LOOKER_DASHBOARD_PATH

    looker = Looker(LOOKER_HOST, LOOKER_EMBED_SECRET)
    user = User(
        user_id,
        first_name=first_name,
        last_name=last_name,
        permissions=json.loads(permissions),
        models=json.loads(models),
        group_ids=json.loads(group_ids),
        external_group_id=external_group_id,
        user_attributes=json.loads(user_attributes),
        access_filters=json.loads(access_filters),
    )

    url = URL(looker, user, session_length, embed_url, force_logout_login=True)

    embed_url = "https://" + url.to_string()

    return jsonify({"embed_url": embed_url})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=9607)
