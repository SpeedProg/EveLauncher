from urllib.error import URLError
import json

__author__ = 'SpeedProg'
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timedelta, timezone
import shelve
import urllib.request
from email._parseaddr import mktime_tz
from email.utils import parsedate_tz


class ShelveCache:
    def __init__(self, filename):
        self.filename = filename

    def set_api_element(self, element):
        with shelve.open(self.filename) as db:
            db[element.api_name] = element

    def get_api_element(self, element_name):
        with shelve.open(self.filename) as db:
            if element_name in db:
                element = db[element_name]
                if element.is_good():
                    return element

                return None
            else:
                return None


class ApiElement:
    element_name = "basic"

    def __init__(self, api_name):
        self.api_name = api_name
        self.good_until = datetime.now(timezone.utc)

    def set_good_until(self, date):
        self.good_until = date

    """
        margin: in seconds
    """

    def is_good(self, margin=0):
        time_delta = timedelta(0, margin)
        current_time = datetime.now(timezone.utc)
        return self.good_until - current_time > time_delta


class ServerStatusApi(ApiElement):
    element_name = "server_status"

    def __init__(self):
        super().__init__(ServerStatusApi.element_name)

        self.url = "https://esi.evetech.net/latest/status/?datasource=tranquility"
        try:
            resp = urllib.request.urlopen(self.url)
            res = json.loads(resp.read().decode('utf-8'))
        except URLError as e:
            print(e)
            self.online_players = 0
            self.version = None
            self.cached_until = (datetime.now(timezone.utc) +
                                 timedelta(minutes=10))
            self.set_good_until(self.cached_until)
            return

        self.online_players = res['players'] if 'players' in res else 0
        self.version = res['server_version'] if 'server_version' in res else None
        header = resp.info()
        if 'expires' in header:
            self.cached_until = ServerStatusApi.header_to_datetime(header['expires'])
            self.set_good_until(datetime.now(timezone.utc)+timedelta(minutes=1))
        else:
            self.cached_until = None
            self.set_good_until(datetime.now(timezone.utc)+timedelta(minutes=1))

    @staticmethod
    def header_to_datetime(header) -> datetime:
        return datetime.fromtimestamp(mktime_tz(parsedate_tz(header)))


class EveApi:
    cache = ShelveCache("api_cache")

    def __init__(self):
        pass

    @staticmethod
    def get_server_status():
        try:
            element = EveApi.cache.get_api_element(
                ServerStatusApi.element_name)
        except EOFError:
            element = ServerStatusApi()
            EveApi.cache.set_api_element(element)
            return element

        if element is not None:
            return element

        element = ServerStatusApi()
        EveApi.cache.set_api_element(element)
        return element
