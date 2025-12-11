# import standard libraries
import json
import random
import base64

# this is for flask web server
# probably different than the one in the server
import flask

# requests library for HTTP requests
import requests

# this is needed for argon2 hashing of uids
from argon2.low_level import Type, hash_secret

# import the standard library parser
# needed for HTML parsing
from html.parser import HTMLParser

# the params for argon2 hashing we were using
DEFAULT_PARAMS = dict(
    time_cost=2, memory_cost=2097152, parallelism=4, hash_len=32, type=Type.ID
)

# the salt we were using
# not actually secret, it is stored as part of the hash as well
SALT = base64.b64decode("2p4gW1kQc3+daOMV7G50NA==")


# same as in the desktop app
def compute_hash(uid):
    uid = str(int(uid, 16))
    return (
        hash_secret(
            secret=uid.encode(),
            salt=SALT,
            **DEFAULT_PARAMS,
        )
        .replace(b",", b"__")
        .decode()
    )


# define a parser class from standard library
# can be used a library for easier parsing
class OdtuParser(HTMLParser):
    def __init__(self):
        super().__init__()
        # storage for token and uid
        self.token = None
        self.uid = None

        # flag for being inside submit button
        self._in_submit_btn = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        # logic for finding the Verification Token
        if tag == "input" and attrs.get("name") == "__RequestVerificationToken":
            app.logger.warning(f"Found token: {attrs.get('value')}")
            self.token = attrs.get("value")

        # logic for finding the Submit Button
        if tag == "button" and attrs.get("type") == "submit":
            self._in_submit_btn = True

    def handle_data(self, data):
        # capture text inside the submit button
        if not self._in_submit_btn or self.uid is not None:
            return

        # check if data looks like a uid
        data = data.strip()
        if not data:
            return

        # check if data is hex
        try:
            int(data, 16)
        except ValueError:
            return

        # store uid
        self.uid = data

    def handle_endtag(self, tag):
        # reset flag when leaving button
        if tag == "button":
            self._in_submit_btn = False


app = flask.Flask(__name__)


def captcha():
    # create a session
    session = requests.Session()

    # get the login page
    login_url = "https://odtucard.metu.edu.tr/User/Login"
    response = session.get(login_url)
    html = response.text

    # use the custom parser to find the token
    parser = OdtuParser()
    parser.feed(html)
    token = parser.token

    # handle case where token might not be found
    if not token:
        app.logger.error("Could not find RequestVerificationToken")
        return {"error": "token_not_found"}, 500

    # no idea why random is needed here
    captcha_id = str(random.random())
    captcha_url = f"https://odtucard.metu.edu.tr/Captcha/CaptchaImage?I={captcha_id}"

    # get the captcha image
    response = session.get(captcha_url)
    captcha = response.content

    # serialize cookies, captcha bound to asp forgery cookies
    cookies = dict(session.cookies.get_dict())

    return {
        "token": token,
        "cookies": cookies,
        "captcha_img": base64.b64encode(captcha).decode(),
    }


def fetch_hash(sid, token, captcha, cookies):
    # recreate the session with cookies
    session = requests.Session()
    cookies = json.loads(cookies)
    for key, value in cookies.items():
        session.cookies.set(key, value)

    # perform login
    login_ctrl_url = "https://odtucard.metu.edu.tr/User/LoginControl"
    payload = {
        "__RequestVerificationToken": token,
        "LOGIN_FIELD": "SICILNO",
        "CAPTCHA": str(captcha),
        "SICILNO": str(sid),
    }
    response = session.post(
        login_ctrl_url,
        data=payload,
    )

    # parse response JSON
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        app.logger.error("Could not parse login response as JSON")
        return {"ret": "invalid_login_response"}

    # check for login errors
    login_err = response_json.get("Err", "")

    if login_err == "Lütfen Doğrulama Kodunu Doğru Giriniz":
        app.logger.warning(f"Captcha failed: {sid} {captcha}")
        return {"ret": "captcha_fail"}
    elif login_err == "[Hata_SicilKaydiBulunamadi]":
        app.logger.warning(f"No such user: {sid}")
        return {"ret": "no_such_user"}
    elif login_err == "[Hata_SicilKampusKartKullanamaz]":
        app.logger.warning(f"User cannot use card: {sid}")
        return {"ret": "cannot_use_card"}
    elif login_err != "":
        app.logger.error(f"Unknown login error: {login_err}")
        return {"ret": "unknown_login_error", "err": login_err}

    # get karts page
    personel_url = "https://odtucard.metu.edu.tr/Home/Kartlar"
    response = session.post(personel_url)
    html = response.text

    # parse the returned HTML to find the UID
    parser = OdtuParser()
    parser.feed(html)
    ret_uid = parser.uid

    # if something went wrong
    if not ret_uid:
        app.logger.error("Could not parse UID from button")
        return {"ret": "parse_error"}

    # normalize uid
    ret_uid = ret_uid.strip().lower()

    # compute hash
    ret_hash = compute_hash(ret_uid)

    return {
        "ret": "success",
        "sid": sid,
        "uid": ret_uid,
        "hash": ret_hash,
    }


# define flask routes
@app.post("/captcha")
def page_captcha():
    return captcha()


@app.post("/fetch_hash")
def page_fetch_hash():
    # get form data
    sid = flask.request.form.get("sid")
    token = flask.request.form.get("token")
    captcha = flask.request.form.get("captcha")
    cookies = flask.request.form.get("cookies")

    # call verify function
    result = fetch_hash(sid, token, captcha, cookies)
    return result


@app.get("/")
def example_app():
    return flask.send_file("example_app.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0")
