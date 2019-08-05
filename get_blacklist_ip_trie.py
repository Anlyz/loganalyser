#!/usr/bin/env python3
"""
Copyright© Anlyz Inc.,
Log analyser analyses csv logs with a particular format to provide security analytics.
Update BL DB: This file is to update the blacklist ip addresses
Version: 1.1
Changelog:
    v0.1        Initial Framework
    v0.9        slice window (in seconds)
    v1.0        command line options
    v1.1        Final Release
"""
import os
import time
import sys
import pygtrie as trie
from joblib import dump
try:
    import re2 as re
except:
    import re

try:
    from config import BLACKLISTED_IP_FILE, BLACKLISTED_IP_TRIE_JOBLIB
except:
    print('* Config file not found! Error!')
    sys.exit(1)

IP_PATTERN = r'((((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))([^0-9]|$))|(((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?))'


def create_blacklist_ip_trie():
    print('* Creating Blacklist IP Trie.')
    print('* Last update: {}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(BLACKLISTED_IP_FILE)))))
    blip = None
    with open(BLACKLISTED_IP_FILE, 'r') as f:
        blip = f.readlines()
    blacklisted_ip_trie = trie.CharTrie()
    for row in blip:
        re_obj = re.search(IP_PATTERN, row)
        if re_obj is not None:
            matched_ip = row[re_obj.span()[0]:re_obj.span()[1]].split('\t')[0]
            blacklisted_ip_trie[matched_ip] = True
    dump(blacklisted_ip_trie, BLACKLISTED_IP_TRIE_JOBLIB)
    print('* Blacklist IP Trie created.')


if __name__ == '__main__':
    try:
        create_blacklist_ip_trie()
    except Exception as e:
        print('* ERROR IN CREATING TRIE : ', e)
        sys.exit(1)
