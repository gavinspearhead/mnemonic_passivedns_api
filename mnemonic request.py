import argparse
import logging
from datetime import datetime

import requests

logging.getLogger().setLevel(logging.INFO)


class MnemonicEntry:

    def __init__(self, data):
        self.data = data

    def __repr__(self):
        return " ".join([self.query, self.answer, self.rrtype, str(self.firstseen), str(self.lastseen), self.rrclass,
                         str(self.times), str(self.ttl)])

    def __str__(self):
        return ", ".join(
            [self.query, self.answer, self.rrtype, str(self.firstseen), str(self.lastseen), str(self.times)])

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
        return self['rrtype'].upper()

    @property
    def rrclass(self):
        return self['rrclass'].upper()

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

    def __init__(self, api_key=None):

        if api_key:
            self.headers['Argus-API-Key'] = api_key

    def __call__(self, search_term, limit=100, offset=0, rrtype=None, rrclass=None):
        data = {
            "query": search_term,
            "aggregateResult": True,
            "includeAnonymousResults": True,
            "rrClass": [] if rrclass is None else [r.lower() for r in rrclass],
            "rrType": [] if rrtype is None else [r.lower() for r in rrtype],
            "customerID": [],
            "tlp": [],
            "offset": int(offset),
            "limit": int(limit)
        }
        res = requests.post(self.url, headers=self.headers, json=data)
        json_val = res.json()
        logging.info("{}+{}/{} Elements retrieved".format(json_val['offset'], json_val['size'], json_val['count']))
        if res.status_code == 200:
            return list(map(MnemonicEntry, json_val['data']))
        else:
            logging.error(json_val['messages'][0]['message'])
            raise ValueError(json_val['messages'][0]['message'])


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Access to Mnemonic Passive DNS API")
    parser.add_argument('-l', '--limit', metavar='L', type=int, help="limit the number of results", default=100)
    parser.add_argument('-o', '--offset', metavar='O', type=int, help="offset the number of results", default=0)
    parser.add_argument('name', metavar='N', type=str, help="name to lookup")
    parser.add_argument('-a', '--all', help="Iterate through all results", action='store_true')
    parser.add_argument('-r', '--rrtype', help="RR types to look up", default=[], nargs='+')
    parser.add_argument('-c', '--rrclass', help="RR classes to look up", default=[], nargs='+')
    args = parser.parse_args()

    search_term = args.name

    m = Mnemonic()
    results = []
    try:
        if args.all:
            if args.limit <= 0:
                args.limit = 100
            offset = 0
            while True:
                res = m(search_term, args.limit, offset)
                if not res:
                    break
                results += res
                offset += args.limit
        else:
            results = m(search_term, args.limit, args.offset, args.rrtype, args.rrclass)

        for x in results:
            print(x)
    except ValueError as e:
        print(e)
        pass
