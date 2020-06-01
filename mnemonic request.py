import sys
from datetime import datetime
from pprint import pprint

import requests


class MnemonicEntry:

    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return self.data

    def __str__(self):
        return " ".join([self.query, self.answer, self.rrtype])

    def __getitem__(self, item):
        return self.data[item]

    @property
    def times(self):
        return self['times']

    @property
    def ttl(self):
        return (self['minTtl'], self['maxTtl'])

    @property
    def firstseen(self):
        ms = self['firstSeenTimestamp']
        return datetime.utcfromtimestamp(ms // 1000).replace(microsecond=ms % 1000 * 1000)

    @property
    def lastseen(self):
        ms = self['lastSeenTimestamp']
        return datetime.utcfromtimestamp(ms // 1000).replace(microsecond=ms % 1000 * 1000)

    @property
    def query(self):
        return self['query']

    @property
    def rrtype(self):
        return self['rrtype']

    @property
    def rrclass(self):
        return self['rrclass']

    @property
    def answer(self):
        return self['answer']


class Mnemonic:
    url = 'https://api.mnemonic.no/pdns/v3/search'

    headers = {
        "Accept": "application/json",
        "Referer": "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0",
        "content-type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0"
    }

    def __call__(self, search_term):
        data = {
            "query": search_term,
            "aggregateResult": True,
            "includeAnonymousResults": True,
            "rrClass": [],
            "rrType": [],
            "customerID": [],
            "tlp": [],
            "offset": 0,
            "limit": 25000
        }
        res = requests.post(self.url, headers=self.headers, json=data)
        if res.status_code == 200:
            return map(MnemonicEntry, res.json()['data'])
        else:
            return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        exit()
    search_term = sys.argv[1]

    m = Mnemonic()
    res = m(search_term)
    for x in res:
        print(x.lastseen, x.firstseen, x.answer, x.query, x.rrtype)
