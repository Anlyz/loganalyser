#!/usr/bin/env python3
"""
Copyright© Anlyz Inc.,
Log analyser analyses csv logs with a particular format to provide security analytics.
O365: This file is to provide security analytics from the O365 logs
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
import warnings
warnings.simplefilter(action='ignore')

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


class O365LogAnalyzer:
    def __init__(self):
        try:
            self.blacklisted_ip = load(BLACKLISTED_IP_TRIE_JOBLIB)
            self.timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
        except Exception as e:
            print('* ERROR IN READING GEOIP DATABASE : ', e)
            sys.exit(1)

    def read_csv_file(self, file_name):
        try:
            print('* Reading log file...')
            self.data = pd.read_csv(file_name)
            return True
        except Exception as e:
            print('* ERROR IN READING CSV FILE : ', e)
            return False

    def verify_columns(self):
        print('* Columns check...')
        columns = self.data.columns.values
        if set(columns) == O365_LOG_STD_COLS:
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

    def check_blacklisted_ip(self, ip):
        return ip in self.blacklisted_ip

    def failed_successful_login_count(self):
        """
        Use-case:- Failed & Successful Login count
        :return:
        """
        failed_login_df = self.data.loc[self.data['loginStatus'] == 'Failure', :].groupby(['user'])['ipAddress']\
                                .count()\
                                .reset_index(name='failed_login_count')\
                                .sort_values(['failed_login_count'], ascending=False)
        successful_login_df = self.data.loc[self.data['loginStatus'] == 'Success', :].groupby(['user'])['ipAddress']\
                                .count()\
                                .reset_index(name='successful_login_count')\
                                .sort_values(['successful_login_count'], ascending=False)
        failed_login_df = pd.merge(failed_login_df, successful_login_df, how='outer', on='user').fillna(0).sort_values(by='user')
        failed_login_df.to_csv(os.path.join(OUTPUT_DIR, 'SuccessFailureLoginCount_' + self.timestamp + '.csv'), index=None)

    def failed_login_based_on_os(self, df):
        df = df.groupby(['user', 'os'])\
               .rolling(WINDOW_SLICE)\
               .agg({'loginStatus': 'count'})\
               .groupby(['user', 'os'])\
               .max()\
               .reset_index()
        df = df.rename(columns={'loginStatus': 'failed_login_count'})
        df = df.sort_values(by='user')
        df.to_csv(os.path.join(OUTPUT_DIR, 'FailedLoginFromDifferentOS_' + self.timestamp + '.csv'), index=None)

    def failed_login_based_on_ip(self, df):
        df = df.groupby(['user','ipAddress'])\
               .rolling(WINDOW_SLICE)\
               .agg({'loginStatus': 'count'})\
               .groupby(['user', 'ipAddress'])\
               .max()\
               .reset_index()
        df = df.rename(columns={'loginStatus': 'failed_login_count'})
        df = df.sort_values(by='user')
        df['mal_ip'] = df['ipAddress'].map(lambda x: self.check_blacklisted_ip(x))
        df = df[['user', 'ipAddress', 'mal_ip', 'failed_login_count']]
        df.to_csv(os.path.join(OUTPUT_DIR, 'FailedLoginFromDifferentIP_' + self.timestamp + '.csv'), index=None)

    def max_login_failure_time_window(self, df):
        df = df.groupby(['user'])\
                .rolling('60s')\
                .agg({'loginStatus': 'sum'})\
                .groupby(['user'])\
                .max()\
                .sort_values(by='loginStatus', ascending=False)\
                .reset_index()
        df = df.rename(columns={'loginStatus': 'failed_login_count'})
        df.to_csv(os.path.join(OUTPUT_DIR, 'MaxLoginFailureByEachUserInWindowedTimeFrame_' + self.timestamp + '.csv'), index=None)

    def split_device_info_column(self):
        sys_df = self.data['deviceInformation'].str.split(';', expand=True).drop(3,axis=1)
        sys_df = sys_df.rename(columns={0:'system', 1:'os', 2:'browser'})
        self.data = pd.concat([self.data, sys_df], sort=False, axis=1)

    def perform_analysis(self, file_name):
        if self.read_csv_file(file_name):
            if self.verify_columns():
                if self.datetime_index():
                    try:
                        print('* Profiling...')
                        self.failed_successful_login_count()
                        self.split_device_info_column()
                        failed_login_df = self.data.loc[self.data['loginStatus'] == 'Failure', :]
                        failed_login_df['loginStatus'] = 1
                        self.failed_login_based_on_os(failed_login_df)
                        self.failed_login_based_on_ip(failed_login_df)
                        self.max_login_failure_time_window(failed_login_df)
                    except Exception as e:
                        print('* ERROR IN PERFORMING ANALYSIS : ', e)
                        sys.exit(1)
            else:
                print('* Invalid columns found!')
                print('* Column names must be : ', O365_LOG_STD_COLS)
                sys.exit(1)


if __name__ == '__main__':
    print('* {}  v{}: O365'.format(__prog__, __version__))
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
        ola = O365LogAnalyzer()
        ola.perform_analysis(file_name)
    else:
        print('* Example: ')
        print('* {} /path/to/log_file.csv'.format(__file__))
        sys.exit(1)
