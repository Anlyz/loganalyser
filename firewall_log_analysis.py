#!/usr/bin/env python3
"""
Copyright© Anlyz Inc.,
Log analyser analyses csv logs with a particular format to provide security analytics.
Firewall: This file is to provide security analytics from the firewall logs
Version: 1.1
Changelog:
    v0.1        Initial Framework
    v0.9        slice window (in seconds)
    v1.0        command line options
    v1.1        Final Release
"""
import sys
import argparse
import numpy as np
import pandas as pd
import geoip2.database
from joblib import load
import datetime

try:
    from config import *
    from config import __prog__, __version__
except:
    print('* Config file not found! Error!')
    sys.exit(1)

try:
    from utils import *
except:
    print('* Utils file not found! Error!')
    sys.exit(1)


class FirewallLogAnalyzer:
    """
    Firewall Log Analyser
    """
    def __init__(self):
        try:
            self.geo_ip_reader = geoip2.database.Reader(GEOLITE_DB)
            self.blacklisted_ip = load(BLACKLISTED_IP_TRIE_JOBLIB)
            self.timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
        except Exception as e:
            print('* ERROR IN READING GEOIP DATABASE : ', e)
            sys.exit(1)

    def read_csv_file(self, file_name):
        try:
            print('* Reading log file...')
            self.data = pd.read_csv(file_name)
            self.data = self.data.loc[self.data['action'] == 'blocked', :]
            self.data['action'] = 1
            return True
        except Exception as e:
            print('* ERROR IN READING CSV FILE : ', e)
            return False

    def verify_columns(self):
        print('* Columns check...')
        columns = self.data.columns.values
        if set(columns) == LOG_STD_COLS:
            return True
        return False

    def datetime_index(self):
        try:
            self.data['_time'] = pd.to_datetime(self.data['_time'])
            self.data = self.data.sort_values(by='_time')
            self.data.index = self.data['_time']
            self.data = self.data.drop('_time', axis=1)
            return True
        except Exception as e:
            print('* ERROR IN CONVERTING INDEX TO DATETIME : ', e)
            return False

    def get_geo_location(self, ip):
        if not is_ip_private(ip):
            try:
                response = self.geo_ip_reader.city(ip)
                country = response.country.name
                city = response.city.name
                if country is None:
                    country = 'NA'
                if city is None:
                    city = 'NA'
                return country, city
            except Exception as e:
                print('* ERROR IN CONVERTING IP TO LOCATION : {}'.format(e))
                return 'NA', 'NA'
        else:
            return 'NA', 'NA'

    def get_country_city(self, location):
        country = []
        city = []
        for row in location.values:
            country.append(row[0])
            city.append(row[1])
        return country, city

    def check_blacklisted_ip(self, ip):
        return ip in self.blacklisted_ip

    def src_ip_analysis(self):
        """
        Use-case:- Analytics based on Source IP. Look for all connections from source-ip perspective
        Includes the count, whether blacklisted or not, country, etc...
        :return:
        """
        src_df = self.data.groupby(['src_ip', 'dest_ip', 'dest_port'])\
                        .rolling(WINDOW_SLICE)\
                        .agg({'action': 'count'})\
                        .groupby(['src_ip', 'dest_ip', 'dest_port'])\
                        .max()\
                        .reset_index()
        src_df = src_df.rename(columns={'action': 'traffic_count'})
        src_df['bl_src_ip'] = src_df['src_ip'].map(lambda x: self.check_blacklisted_ip(x))
        src_df['bl_dest_ip'] = src_df['dest_ip'].map(lambda x: self.check_blacklisted_ip(x))
        dest_location = src_df['dest_ip'].map(lambda x: self.get_geo_location(x))
        dest_country, dest_city = self.get_country_city(dest_location)
        src_location = src_df['src_ip'].map(lambda x: self.get_geo_location(x))
        src_country, src_city = self.get_country_city(src_location)
        src_df['dest_country'] = dest_country
        src_df['dest_city'] = dest_city
        src_df['src_country'] = src_country
        src_df['src_city'] = src_city
        src_df = src_df[['src_country', 'src_city', 'src_ip', 'bl_src_ip',
                         'dest_country', 'dest_city', 'dest_ip', 'bl_dest_ip',
                         'dest_port', 'traffic_count']]
        src_df.to_csv(os.path.join(OUTPUT_DIR, 'BlockedTrafficForEachSourceIP_' + self.timestamp + '.csv'), index=None)

    def dest_ip_analysis(self):
        """
        Use-case:- Analytics based on Destination IP.
        :return:
        """
        dest_df = self.data.groupby(['dest_ip', 'dest_port'])\
                        .rolling(WINDOW_SLICE)\
                        .agg({'action': 'count'})\
                        .groupby(['dest_ip', 'dest_port'])\
                        .max()\
                        .reset_index()
        dest_df = dest_df.rename(columns={'action': 'traffic_count'})
        dest_df['bl_dest_ip'] = dest_df['dest_ip'].map(lambda x: self.check_blacklisted_ip(x))
        dest_location = dest_df['dest_ip'].map(lambda x: self.get_geo_location(x))
        dest_country, dest_city = self.get_country_city(dest_location)
        dest_df['dest_country'] = dest_country
        dest_df['dest_city'] = dest_city
        dest_df = dest_df[['dest_country', 'dest_city', 'dest_ip', 'bl_dest_ip',
                           'dest_port', 'traffic_count']]
        dest_df.to_csv(os.path.join(OUTPUT_DIR, 'BlockedTrafficForEachDestinationIP_' + self.timestamp + '.csv'), index=None)

    def perform_analysis(self, file_name):
        """
        Begin analytics for the provided log file.
        :param file_name:
        :return:
        """
        if self.read_csv_file(file_name):
            if self.verify_columns():
                if self.datetime_index():
                    try:
                        print('* Profiling...')
                        self.src_ip_analysis()
                        self.dest_ip_analysis()
                    except Exception as e:
                        print('* ERROR IN PERFORMING ANALYSIS : ', e)
                        sys.exit(1)
            else:
                print('* Invalid columns found!')
                print('* Column names must be : ', LOG_STD_COLS)
                sys.exit(1)


if __name__ == '__main__':
    print('* {}  v{}: Firewall'.format(__prog__, __version__))
    print('* Update the Blacklisted IP database if you haven\'t done so in the last 24hrs!')
    parser = argparse.ArgumentParser(description=__prog__, prog=__prog__)
    parser.add_argument('filename')
    parser.add_argument('-w', '--window-slice', default=WINDOW_SLICE, help='Time Window bucket in seconds')
    args = parser.parse_args()
    WINDOW_SLICE = args.window_slice
    WINDOW_SLICE = check_window_slice(WINDOW_SLICE)

    if not os.access(RESOURCES_DIR, os.F_OK):
        print("* Error accessing '{}' folder! Exiting...!".format(RESOURCES_DIR))
        sys.exit(1)

    is_dirs(ML_DIR, OUTPUT_DIR)  # check if folders exist, else create them

    if args.filename:
        file_name = args.filename
        if not os.access(file_name, os.F_OK):
            print("* Error accessing '{}'! Exiting...!".format(file_name))
            sys.exit(1)

        print('* params:')
        print('  --window-slice: {}'.format(WINDOW_SLICE))
        fa = FirewallLogAnalyzer()
        fa.perform_analysis(file_name)
    else:
        print('* Example: ')
        print('* {} /path/to/log_file.csv'.format(__file__))
        sys.exit(1)
