#!/usr/bin/env python3
"""
Copyright© Anlyz Inc.,
Log analyser analyses csv logs with a particular format to provide security analytics.
Update IP TO ISP DB: This file is to update the ip addresses to isp database.
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
import io
import requests
from joblib import dump
import radix
try:
    import re2 as re
except:
    import re

try:
    from config import IP_ASN_URL, ASN_ISP_URL, IP_ISP_RTREE_JOBLIB
except:
    print('* Config file not found! Error!')
    sys.exit(1)


def download_file(url):
    try:
        r = requests.get(url, stream=True)
        r = r.text.split('\n')
        r = r[:-1]
        return r
    except Exception as e:
        print('* ERROR IN DOWNLOADING FILE : ', e)
        sys.exit(1)

def create_asn_to_isp_dict():
    data = download_file(ASN_ISP_URL)
    asn_isp_dic = dict()
    try:
        for row in data:
            tokens = row.strip().split(' ',1)
            asn_isp_dic[int(tokens[0])] = tokens[1]
        return asn_isp_dic
    except Exception as e:
        print('* ERROR IN CREATING ASN TO ISP DICTIONARY :', e)
        sys.exit(1)

def create_ip_to_asn_dict():
    asn_isp_dic = create_asn_to_isp_dict()
    data = download_file(IP_ASN_URL)
    rtree = radix.Radix()
    try:
        for row in data:
            tokens = row.split('\t')
            rnode = rtree.add(tokens[0].strip())
            try:
                rnode.data['isp'] = asn_isp_dic[int(tokens[1].strip())]
            except:
                rnode.data['isp'] = 'UNKNOWN'
        return rtree
    except Exception as e:
        print('* ERROR IN CREATING RADIX TREE : ', e)
        sys.exit(1)

def dump_radix_tree():
    rtree = create_ip_to_asn_dict()
    dump(rtree, IP_ISP_RTREE_JOBLIB)

def create_ip_to_isp_rtree():
    print('* Creating IP to ISP Radix Tree.')
    try:
        print('* Last update: {}'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(IP_ISP_RTREE_JOBLIB)))))
    except:
        pass
    try:
        dump_radix_tree()
        print('* IP to ISP Radix Tree created.')
    except Exception as e:
        print('* ERROR IN CREATING IP TO ISP RADIX TREE : ', e)
        sys.exit(1)

if __name__ == '__main__':
    try:
        create_ip_to_isp_rtree()
    except Exception as e:
        print('* ERROR IN CREATING RADIX TREE : ', e)
        sys.exit(1)
