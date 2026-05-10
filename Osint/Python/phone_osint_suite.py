#!/usr/bin/env python3

import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import sys
import requests
import json

class PhoneOSINT:
    def __init__(self, number):
        self.number = number
        self.parsed = None

    def parse(self):
        try:
            self.parsed = phonenumbers.parse(self.number, None)
            return True
        except:
            return False

    def country(self):
        return geocoder.description_for_number(self.parsed, "en")

    def carrier_info(self):
        return carrier.name_for_number(self.parsed, "en")

    def time_zones(self):
        return timezone.time_zones_for_number(self.parsed)

    def numverify(self, api_key=None):
        if not api_key:
            return
        url = f"http://apilayer.net/api/validate?access_key={api_key}&number={self.number}"
        r = requests.get(url)
        if r.status_code == 200:
            return r.json()

    def callouts(self):
        # Check against known breach APIs (example: HaveIBeenPwned phone? not supported)
        # Just placeholder
        pass

    def run(self):
        if not self.parse():
            print("[-] Invalid number")
            return
        print(f"[+] Country: {self.country()}")
        print(f"[+] Carrier: {self.carrier_info()}")
        print(f"[+] Timezones: {self.time_zones()}")
        # Generate possible variations
        national = phonenumbers.format_number(self.parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        international = phonenumbers.format_number(self.parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        e164 = phonenumbers.format_number(self.parsed, phonenumbers.PhoneNumberFormat.E164)
        print(f"[+] E.164: {e164}")
        print(f"[+] International: {international}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: phone_osint_suite.py +1234567890")
        sys.exit(1)
    po = PhoneOSINT(sys.argv[1])
    po.run()