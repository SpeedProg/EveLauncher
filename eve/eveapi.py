__author__ = 'SpeedProg'
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
import shelve
import urllib.request


class ShelveCache():
    def __init__(self, filename):
        self.filename = filename
        self.db = None

    def open(self):
        self.db = shelve.open(self.filename)

    def close(self):
        self.db.close()

    def set_api_element(self, element):
        self.db[element.api_name] = element

    def get_api_element(self, element_name):
        if element_name in self.db:
            element = self.db[element_name]
            if element.is_good():
                return element

            return None
        else:
            return None


class ApiElement():

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
        self.url = "https://api.eveonline.com/server/ServerStatus.xml.aspx"
        self.api_data = urllib.request.urlopen(self.url).read()
        root = ET.fromstring(self.api_data)
        self.current_time = None
        self.server_open = False
        self.online_players = 0
        self.cached_until = None

        for child in root:
            if child.tag == 'currentTime':
                self.parse_current_time(child)

            if child.tag == 'result':
                self.parse_result(child)

            if child.tag == 'cachedUntil':
                self.parse_cached_until(child)

        time_delta = self.cached_until - self.current_time
        good_until = datetime.now(timezone.utc)+time_delta
        self.set_good_until(good_until)

    def parse_current_time(self, element):
        self.current_time = datetime.strptime(element.text, "%Y-%m-%d %H:%M:%S")

    def parse_result(self, element):
        for child in element:
            if child.tag == 'serverOpen':
                self.parse_server_open(child)

            if child.tag == 'onlinePlayers':
                self.parse_online_players(child)

    def parse_server_open(self, element):
            if element.text == 'True':
                self.server_open = True
            else:
                self.server_open = False

    def parse_online_players(self, element):
        self.online_players = int(element.text)

    def parse_cached_until(self, element):
        self.cached_until = datetime.strptime(element.text, "%Y-%m-%d %H:%M:%S")


class EveApi():
    def __init__(self):
        self.cache = ShelveCache("api_cache")
        self.cache.open()

    def get_server_status(self):
        element = self.cache.get_api_element(ServerStatusApi.element_name)
        if element is not None:
            return element

        element = ServerStatusApi()
        self.cache.set_api_element(element)
        return element

    def close(self):
        self.cache.close()