__author__ = 'SpeedProg'
import urllib.parse
import urllib.request
from urllib.error import *
import http.cookiejar
import datetime
import subprocess
import base64
import hashlib
import shelve

from Crypto import Random
from Crypto.Cipher import AES

from utils.classhelper import AutoStr


class EveAccount(AutoStr):
    """
        Returns a ascii decoded, b64 string, from the input utf-8 password that was encrypted
    """

    @staticmethod
    def crypt_password(coder, password):
        return base64.b64encode(coder.encrypt(password.encode('utf-8'))).decode('ascii')

    """
        Returns a utf-8 decoded, decrypted string from the input b64 ascii encrypted string
    """

    @staticmethod
    def decrypt_password(coder, enc_password):
        return coder.decrypt(base64.b64decode(enc_password.encode('ascii'))).decode('utf-8')

    def __init__(self, loginname, password, coder, evepath, bearer_token, client_token, dx="dx11"):
        self.login_name = loginname
        self.eve_password = EveAccount.crypt_password(coder, password)
        self.eve_path = evepath
        self.direct_x = dx
        self.bearer_token = bearer_token
        self.client_token = client_token

    def plain_password(self, coder):
        return EveAccount.decrypt_password(coder, self.eve_password)


class BearerToken(AutoStr):
    def __init__(self, token, expiration):
        self.token = token
        self.expiration = expiration
        self.type = 'Bearer'

    def token(self):
        return self.token

    def expiration(self):
        return self.expiration


class ClientToken(AutoStr):
    def __init__(self, token, expiration):
        self.token = token
        self.expiration = expiration
        self.type = 'Client'


class NoRedirectHandler(AutoStr, urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        infurl = urllib.request.addinfourl(fp, headers, req.get_full_url())
        infurl.status = code
        infurl.code = code
        return infurl

    http_error_300 = http_error_302
    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302


class Coding(AutoStr):
    def __init__(self, key):
        self.key = hashlib.sha256(key).digest()

    @staticmethod
    def pkcs5_pad(s):
        length = AES.block_size - (len(s) % AES.block_size)
        for x in range(0, length):
            s += bytes([length])

        return s

    @staticmethod
    def pkcs5_unpad(s):
        return s[0:-s[-1]]

    def encrypt(self, raw):
        raw = Coding.pkcs5_pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encD = cipher.encrypt(raw)
        return iv + encD

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[AES.block_size:])
        unpadded = Coding.pkcs5_unpad(decrypted)
        return unpadded


class EveLoginManager(AutoStr):
    url_bearer_token = "https://login.eveonline.com/Account/LogOn?ReturnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3" \
                       + "DeveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2F" \
                       + "login.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken"
    url_client_token = "https://login.eveonline.com/launcher/token?accesstoken="
    bearer_headers = {'Origin': 'https://login.eveonline.com',
                      'Referer': url_bearer_token,
                      'Content-Type': 'application/x-www-form-urlencoded'}
    bearer_min_timedelta = datetime.timedelta(0, 20, 0, 0, 0, 0, 0)  # 20s
    client_min_timedelta = datetime.timedelta(0, 20, 0, 0, 0, 0, 0)  # 20s
    db_acc_prefix = "acc_"

    @staticmethod
    def do_login(account):
        subprocess.Popen([account.eve_path + "bin\exefile.exe", "/noconsole",
                          "/ssoToken={0}".format(account.client_token.token),
                          "/triPlatform={0}".format(account.direct_x)],
                         cwd=account.eve_path)

    @staticmethod
    def bearer_url_from_eve_account(cookie_proc, coder, eve_account):
        opener = urllib.request.build_opener(cookie_proc)

        post_data = {'UserName': eve_account.login_name,
                     'Password': eve_account.plain_password(coder)}

        encoded_post_data = urllib.parse.urlencode(post_data).encode('utf-8')

        request = urllib.request.Request(EveLoginManager.url_bearer_token, encoded_post_data,
                                         EveLoginManager.bearer_headers)

        response = opener.open(request)
        return response.geturl()

    @staticmethod
    def bearer_token_from_url(url):
        parsed_token_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_token_url.fragment)

        if 'expires_in' in params and 'access_token' in params:
            expires_in = datetime.timedelta(0, int(params['expires_in'][0]), 0, 0, 0, 0, 0)
            date_now = datetime.datetime.now(datetime.timezone.utc)
            return BearerToken(params['access_token'][0], date_now + expires_in)
        else:
            raise HTTPError(url, 403, "Login data wrong!", "", "")

    @staticmethod
    def client_token_from_bearer_token(cookie_proc, bearer_token):
        url = EveLoginManager.url_client_token + bearer_token.token
        request = urllib.request.Request(url)
        # don't redirect this anymore
        opener = urllib.request.build_opener(cookie_proc, NoRedirectHandler)
        response = opener.open(request)
        location = response.info()['Location']
        parsed_url = urllib.parse.urlparse(location)
        params = urllib.parse.parse_qs(parsed_url.fragment)
        expires_in = datetime.timedelta(0, int(params['expires_in'][0]), 0, 0, 0, 0, 0)
        date_now = datetime.datetime.now(datetime.timezone.utc)
        return ClientToken(params['access_token'][0], date_now + expires_in)

    def __init__(self, coder):
        self.accounts = dict()
        self.coder = coder
        self.db = shelve.open("settings.v2")

    def __del__(self):
        self.db.close()

    """
        @account EveAccount
    """

    def add_account(self, account):
        self.accounts[account.login_name] = account

    """
        @login_name String loginname
    """

    def del_account(self, login_name):
        del self.accounts[login_name]
        print(self.accounts)
        if (EveLoginManager.db_acc_prefix + login_name) in self.db:
            del self.db[EveLoginManager.db_acc_prefix + login_name]

    def login(self, loginname):
        account = self.accounts[loginname]

        # lets check if there is still a valid token
        if account.client_token is not None:
            date_now = datetime.datetime.now(datetime.timezone.utc)
            time_left = account.client_token.expiration - date_now

            if time_left > EveLoginManager.client_min_timedelta:
                EveLoginManager.do_login(account)
                return True

        cookies = http.cookiejar.CookieJar()
        cookie_proc = urllib.request.HTTPCookieProcessor(cookies)

        if account.bearer_token is not None:
            date_now = datetime.datetime.now(datetime.timezone.utc)
            time_left = account.bearer_token.expiration - date_now
            if time_left > EveLoginManager.bearer_min_timedelta:
                try:
                    client_token = EveLoginManager.client_token_from_bearer_token(cookie_proc, account.bearer_token)
                except URLError as e:
                    raise e
                else:
                    print("Tokens received successful")
                    account.client_token = client_token
                    EveLoginManager.do_login(account)
                    return True

        try:
            bearer_token = EveLoginManager.bearer_token_from_url(
                EveLoginManager.bearer_url_from_eve_account(cookie_proc, self.coder, account))
            account.bearer_token = bearer_token
            client_token = EveLoginManager.client_token_from_bearer_token(cookie_proc, bearer_token)
            account.client_token = client_token
        except URLError as e:
            raise e
        else:
            EveLoginManager.do_login(account)

    def save(self):
        for account in self.accounts:
            local_account = self.accounts[account]
            self.db[EveLoginManager.db_acc_prefix + local_account.login_name] = local_account

    def load(self):
        for account_name in self.db.keys():
            if account_name.startswith(EveLoginManager.db_acc_prefix):
                self.add_account(self.db[account_name])
