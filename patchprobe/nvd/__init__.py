from time import sleep

import requests

from .cve import Vulnerability
from .exceptions import NVDClientException, NVDServerException

API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


class NVD:
    def __init__(self, api_key, overrides=None):
        self.api_key = api_key

        if overrides is None:
            overrides = {}
        self.overrides = overrides

        self.cve_index = 0
        self.cve_total = float('inf')

        self.cves = set()

    def fetch_all(self):
        while self.cve_index < self.cve_total:
            try:
                self.fetch()
                print(f'Progress: {len(self.cves)}/{self.cve_total} '
                      f'({float(len(self.cves)) / self.cve_total:.2%}) CVEs')
                sleep(5)
            except NVDClientException:
                print("Client error, retrying in 5 seconds...")
                sleep(5)
                continue
            except NVDServerException:
                print("Server error, retrying in 5 seconds...")
                sleep(5)
                continue

    def fetch(self):
        params = self.overrides | {'startIndex': self.cve_index}
        response = requests.get(
            f'{API_URL}?{"&".join([f"{key}={value}" for key, value in params.items()])}',
            headers={'apiKey': self.api_key})

        if response.status_code // 100 == 2:
            cves = set([Vulnerability(item.get('cve')) for item in response.json().get('vulnerabilities', [])])
            self.cves |= cves

            self.cve_index = response.json().get('startIndex', 0) + response.json().get('resultsPerPage', 0)
            self.cve_total = response.json().get('totalResults', 0)
        elif response.status_code // 100 == 4:
            raise NVDClientException()
        elif response.status_code // 100 == 5:
            raise NVDServerException()
        else:
            print("Excuse me, what?")
