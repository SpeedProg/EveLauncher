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

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os

from utils.classhelper import AutoStr


class EveAccount(AutoStr):
    """
        Returns a ascii decoded, b64 string, from the input utf-8 password that was encrypted
    """

    version = 1

    @staticmethod
    def crypt_password(coder, password):
        return base64.b64encode(coder.encrypt(password.encode('utf-8'))).decode('ascii')

    """
        Returns a utf-8 decoded, decrypted string from the input b64 ascii encrypted string
    """

    @staticmethod
    def decrypt_password(coder, enc_password):
        return coder.decrypt(base64.b64decode(enc_password.encode('ascii'))).decode('utf-8')

    def __init__(self, loginname, password, coder, bearer_token, client_token, dx="dx11", profile_name="default"):
        self.login_name = loginname
        self.eve_password = EveAccount.crypt_password(coder, password)
        self.direct_x = dx
        self.bearer_token = bearer_token
        self.client_token = client_token
        self.profile_name = profile_name
        self.version = EveAccount.version

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
        length = algorithms.AES.block_size - (len(s) % algorithms.AES.block_size)
        for x in range(0, length):
            s += bytes([length])

        return s

    @staticmethod
    def pkcs5_unpad(s):
        return s[0:-s[-1]]

    def encrypt(self, raw):
        raw = Coding.pkcs5_pad(raw)
        iv = os.urandom(int(algorithms.AES.block_size/8))
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encrypt = cipher.encryptor()
        enc = encrypt.update(raw) + encrypt.finalize()
        return iv + enc

    def decrypt(self, enc):
        # first part is our iv
        iv = enc[:int(algorithms.AES.block_size/8)]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decrypt = cipher.decryptor()
        decrypted = decrypt.update(enc[int(algorithms.AES.block_size/8):]) + decrypt.finalize()
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
            '''
            if id_val is not None:
                if id_val == 'AuthenticatorSecret':
                    self.auth_secret = self.get_attr_from_attrs(attrs, 'value')
            '''

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
    useragent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' \
                ' (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36'
    #  base path https://client.eveonline.com/launcherv3/en?steam_token=&server=tranquility

    base_url = "https://login.eveonline.com"
    url_char_challenge = "/Account/Challenge?ReturnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3D" \
                         "eveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2F" \
                         "login.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken%2520user"
    url_bearer_token = "https://login.eveonline.com/Account/LogOn?ReturnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3D" \
                       "eveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2F" \
                       "login.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken%2520user"

    url_client_token = "https://login.eveonline.com/launcher/token?accesstoken="
    bearer_headers = {'User-Agent': useragent,
                      'Origin': 'https://login.eveonline.com',
                      'Referer': url_bearer_token,
                      'Content-Type': 'application/x-www-form-urlencoded'}
    url_eula = "https://login.eveonline.com/oauth/authorize/?client_id=eveLauncherTQ&lang=en&" \
               "response_type=token&redirect_uri=https://login.eveonline.com/launcher?" \
               "client_id=eveLauncherTQ&scope=eveClientToken%20user"
    url_post_eula = "https://login.eveonline.com/oauth/eula"
    url_auth_code = "https://login.eveonline.com/Account/Authenticator?ReturnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3D" \
                    "eveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2F" \
                    "login.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken%2520user"
    url_mail_code = "https://login.eveonline.com/Account/VerifyTwoFactor?ReturnUrl=%2Foauth%2Fauthorize%2F%3F" \
                    "client_id%3DeveLauncherTQ%26lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2F" \
                    "login.eveonline.com%2Flauncher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken%2520user"
    url_send_auth_mail = "/Account/AuthenticationMail?returnUrl=%2Foauth%2Fauthorize%2F%3Fclient_id%3DeveLauncherTQ%26" \
                         "lang%3Den%26response_type%3Dtoken%26redirect_uri%3Dhttps%3A%2F%2Flogin.eveonline.com%2F" \
                         "launcher%3Fclient_id%3DeveLauncherTQ%26scope%3DeveClientToken"

    bearer_min_timedelta = datetime.timedelta(0, 20, 0, 0, 0, 0, 0)  # 20s
    client_min_timedelta = datetime.timedelta(0, 20, 0, 0, 0, 0, 0)  # 20s
    db_acc_prefix = "acc_"

    @staticmethod
    def do_login(account, eve_path):
        subprocess.Popen([eve_path + "bin" + os.sep + "exefile.exe", "/noconsole",
                         "/ssoToken={0}".format(account.client_token.token),
                         "/triPlatform={0}".format(account.direct_x),
                          "/settingsprofile={0}".format(account.profile_name)],
                         cwd=eve_path)

    @staticmethod
    def bearer_url_from_eve_account(cookie_proc, coder, eve_account):
        """
            return 0, url if logged in
            return 1, response, url_data if auth is needed
            return 2, response, url_data if char is needed
        """
        opener = urllib.request.build_opener(cookie_proc)

        post_data = {'Password': eve_account.plain_password(coder),
                     'UserName': eve_account.login_name}

        encoded_post_data = urllib.parse.urlencode(post_data).encode('utf-8')

        request = urllib.request.Request(EveLoginManager.url_bearer_token, encoded_post_data,
                                         EveLoginManager.bearer_headers)

        response = opener.open(request)
        url_data = response.read().decode('utf-8')

        if '/account/authenticator?ReturnUrl' in url_data:  # need auth token
            return 1, response, url_data

        if 'Account/Challenge?' in url_data:  # need account char name
            return 2, response, url_data

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
            raise HTTPError(url, 403, "Login data wrong! " + url, "", "")

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

    def login(self, loginname, auth_code_cb, charname_cb, eve_path):
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
                    EveLoginManager.do_login(account, eve_path)
                    return True

        try:
            ret_data = EveLoginManager.bearer_url_from_eve_account(cookie_proc, self.coder, account)
            token_url = ""
            if ret_data[0] == 1:  # we need auth code
                parser = AuthSiteParser()
                parser.feed(ret_data[2])

                #  create request
                headers = {'User-Agent': EveLoginManager.useragent,
                           'Origin': 'https://login.eveonline.com',
                           'Referer': ret_data[1].geturl()}
                request = urllib.request.Request("https://login.eveonline.com" + EveLoginManager.url_send_auth_mail,
                                                 None, headers)
                opener = urllib.request.build_opener(cookie_proc)
                response, auth_code = auth_code_cb(opener, request)
                if auth_code is not None:
                    post_data = [('Challenge', auth_code), ('RememberTwoFactor', 'true'),
                                 ('RememberTwoFactor', 'false'),
                                 ('command', parser.command)]
                    refurl = ""
                    if response is None:
                        refurl = ret_data[1].geturl()
                        verurl = EveLoginManager.url_auth_code
                    else:
                        refurl = response.geturl()
                        verurl = EveLoginManager.url_mail_code

                    headers = {'User-Agent': EveLoginManager.useragent,
                               'Origin': 'https://login.eveonline.com',
                               'Referer': refurl,
                               'Content-Type': 'application/x-www-form-urlencoded'}
                    encoded_post_data = urllib.parse.urlencode(post_data).encode('utf-8')

                    request = urllib.request.Request(verurl, encoded_post_data, headers)
                    opener = urllib.request.build_opener(cookie_proc)
                    response = opener.open(request)
                    token_url = response.geturl()
                else:
                    return False
            elif ret_data[0] == 2:  # we need charname
                char_name = charname_cb()
                if char_name is not None:
                    post_data = [('Challenge', char_name), ('command', 'Continue')]
                    refurl = ret_data[1].geturl()
                    headers = {'User-Agent': EveLoginManager.useragent,
                               'Origin': 'https://login.eveonline.com',
                               'Referer': refurl,
                               'Content-Type': 'application/x-www-form-urlencoded'}
                    encoded_post_data = urllib.parse.urlencode(post_data).encode('utf-8')
                    request = urllib.request.Request(EveLoginManager.base_url + EveLoginManager.url_char_challenge,
                                                     encoded_post_data, headers)
                    opener = urllib.request.build_opener(cookie_proc)
                    response = opener.open(request)
                    token_url = response.geturl()
                else:
                    return False
            else:
                token_url = ret_data[1]

            if token_url == EveLoginManager.url_eula:
                eula_html = response.read()
                parser = EulaParser()
                parser.feed(eula_html.decode('utf-8'))
                post_data = {'eulaHash': parser.eula_hash, 'returnUrl': parser.return_url}
                encoded_post_data = urllib.parse.urlencode(post_data).encode('utf-8')
                headers = {'User-Agent': EveLoginManager.useragent,
                           'Origin': 'https://login.eveonline.com',
                           'Referer': token_url,
                           'Content-Type': 'application/x-www-form-urlencoded'}
                request = urllib.request.Request(EveLoginManager.url_post_eula, encoded_post_data, headers)
                response = opener.open(request)
                token_url = response.geturl()

            bearer_token = EveLoginManager.bearer_token_from_url(token_url)
            account.bearer_token = bearer_token
            client_token = EveLoginManager.client_token_from_bearer_token(cookie_proc, bearer_token)
            account.client_token = client_token
        except URLError as e:
            raise e
        else:
            EveLoginManager.do_login(account, eve_path)

    def save(self):
        for account in self.accounts:
            local_account = self.accounts[account]
            self.db[EveLoginManager.db_acc_prefix + local_account.login_name] = local_account

    def load(self):
        for account_name in self.db.keys():
            if account_name.startswith(EveLoginManager.db_acc_prefix):
                acc = self.db[account_name]
                # if we are in versioned
                if hasattr(acc, 'version'):
                    # this is where versioned conversions should happen
                    # there is no other versioned thing yet, so just add it
                    # if version matches
                    if acc.version == EveAccount.version:
                        self.add_account(acc)
                else:
                    # unversioned things
                    crypt = Coding("xd".encode('utf-8'))
                    nacc = EveAccount(acc.login_name, " ", crypt, acc.bearer_toke, acc.client_token, acc.direct_x, acc.profile_name)
                    # set the old encoded password
                    nacc.eve_password = acc.eve_password
                    self.add_account(nacc)
