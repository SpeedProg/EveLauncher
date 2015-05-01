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
from html.parser import HTMLParser

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
        enc = cipher.encrypt(raw)
        return iv + enc

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc[AES.block_size:])
        unpadded = Coding.pkcs5_unpad(decrypted)
        return unpadded


class EulaParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.eula_hash = None
        self.return_url = None

    def handle_starttag(self, tag, attrs):
        if tag == 'input':
            id_val = self.get_attr_from_attrs(attrs, 'id')
            if id_val is not None:
                if id_val == 'eulaHash':
                    self.eula_hash = self.get_attr_from_attrs(attrs, 'value')
                if id_val == 'returnUrl':
                    self.return_url = self.get_attr_from_attrs(attrs, 'value')

    @staticmethod
    def get_attr_from_attrs(attrs, attr):
        for a in attrs:
            if a[0] == attr:
                return a[1]
        return None

    def handle_endtag(self, tag):
        pass

    def handle_data(self, data):
        pass


class AuthSiteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.auth_secret = None
        self.command = None
        self.return_url = None

    def handle_starttag(self, tag, attrs):
        if tag == 'input':
            id_val = self.get_attr_from_attrs(attrs, 'id')
            if id_val is not None:
                if id_val == 'AuthenticatorSecret':
                    self.auth_secret = self.get_attr_from_attrs(attrs, 'value')

            name_val = self.get_attr_from_attrs(attrs, 'name')

            if name_val is not None:
                if name_val == 'command':
                    classes = self.get_attr_from_attrs(attrs, 'class')
                    if 'continue' in classes:
                        self.command = self.get_attr_from_attrs(attrs, 'value')

    @staticmethod
    def get_attr_from_attrs(attrs, attr):
        for a in attrs:
            if a[0] == attr:
                return a[1]
        return None

    def handle_endtag(self, tag):
        pass

    def handle_data(self, data):
        pass


class EveLoginManager(AutoStr):
    useragent = 'EVEOnlineLauncher/2.2.859950'
    url_bearer_token = "https://login.eveonline.com/Account/LogOn?ReturnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3" \
                       + "DeveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2F" \
                       + "login.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken"
    url_client_token = "https://login.eveonline.com/launcher/token?accesstoken="
    bearer_headers = {'User-Agent': useragent,
                      'Origin': 'https://login.eveonline.com',
                      'Referer': url_bearer_token,
                      'Content-Type': 'application/x-www-form-urlencoded'}
    url_eula = "https://login.eveonline.com/oauth/authorize/?client_id=eveLauncherTQ&lang=en&" \
               "response_type=token&redirect_uri=https://login.eveonline.com/launcher?" \
               "client_id=eveLauncherTQ&scope=eveClientToken"
    url_post_eula = "https://login.eveonline.com/OAuth/Eula"
    url_auth_code = "https://login.eveonline.com/Account/Authenticator?ReturnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3DeveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2Flogin.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken"
    url_send_auth_mail = "/Account/AuthenticationMail?returnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3DeveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2Flogin.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken"


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
        """
            return 0, url if logged in
            return 1, response, url_data if auth is needed
        """
        opener = urllib.request.build_opener(cookie_proc)

        post_data = {'UserName': eve_account.login_name,
                     'Password': eve_account.plain_password(coder)}

        encoded_post_data = urllib.parse.urlencode(post_data).encode('utf-8')

        request = urllib.request.Request(EveLoginManager.url_bearer_token, encoded_post_data,
                                         EveLoginManager.bearer_headers)

        response = opener.open(request)
        url_data = response.read().decode('utf-8')
        if 'class="checkbox authenticator-checkbox"' in url_data:  # need auth token
            return 1, response, url_data

        url = response.geturl()
        if url == EveLoginManager.url_eula:
            eula_html = response.read()
            parser = EulaParser()
            parser.feed(eula_html.decode('utf-8'))
            post_data = {'eulaHash': parser.eula_hash, 'returnUrl': parser.return_url}
            encoded_post_data = urllib.parse.urlencode(post_data).encode('utf-8')
            headers = {'User-Agent': EveLoginManager.useragent,
                       'Origin': 'https://login.eveonline.com',
                       'Referer': url,
                       'Content-Type': 'application/x-www-form-urlencoded'}
            request = urllib.request.Request(EveLoginManager.url_post_eula, encoded_post_data, headers)
            response = opener.open(request)

        return 0, response.geturl()

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
        if self.db is not None:
            self.db.close()

    def clear_cache(self):
        for acc_key in self.db.keys():
            acc = self.db[acc_key]
            acc.bearer_token = None
            acc.client_token = None
            self.db[acc_key] = acc

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
        if (EveLoginManager.db_acc_prefix + login_name) in self.db:
            del self.db[EveLoginManager.db_acc_prefix + login_name]

    def login(self, loginname, auth_code_cb):
        account = self.accounts[loginname]

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
                    account.client_token = client_token
                    EveLoginManager.do_login(account)
                    return True

        try:
            ret_data = EveLoginManager.bearer_url_from_eve_account(cookie_proc, self.coder, account)
            token_url = ""
            if ret_data[0] == 1:
                parser = AuthSiteParser()
                parser.feed(ret_data[2])
                auth_code = auth_code_cb(EveLoginManager.url_send_auth_mail)
                if auth_code[1]:
                    post_data = [('Challenge', auth_code[0]), ('RememberTwoFactor', 'true'),
                                 ('RememberTwoFactor', 'false'), ('AuthenticatorSecret', parser.auth_secret),
                                 ('command', parser.command)]
                    headers = {'User-Agent': EveLoginManager.useragent,
                               'Origin': 'https://login.eveonline.com',
                               'Referer': ret_data[1].geturl(),
                               'Content-Type': 'application/x-www-form-urlencoded'}
                    encoded_post_data = urllib.parse.urlencode(post_data).encode('utf-8')
                    request = urllib.request.Request(EveLoginManager.url_auth_code, encoded_post_data, headers)
                    opener = urllib.request.build_opener(cookie_proc)
                    response = opener.open(request)
                    token_url = response.geturl()
                else:
                    return False
            else:
                token_url = ret_data[1]
            bearer_token = EveLoginManager.bearer_token_from_url(token_url)
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
