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
import sys
import argparse
import numpy as np
import pandas as pd
from joblib import load
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
import datetime
import warnings
from tqdm import tqdm
warnings.simplefilter(action='ignore')

try:
    from config import *
    from config import __prog__, __version__
except:
    print('* Config file not found! Error!')
    sys.exit(1)

try:
    from utils import is_dirs
except:
    print('* Utils file not found! Error!')
    sys.exit(1)

class O365AnomalyDetector:
    def __init__(self):
        try:
            self.rtree = load(IP_ISP_RTREE_JOBLIB)
            self.timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
        except Exception as e:
            print('* ERROR IN READING TP TO ISP RADIX TREE : ', e)
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

    def extract_date_hour(self):
        try:
            self.data['_time'] = pd.to_datetime(self.data['_time'])
            self.data = self.data.sort_values(by='_time')
            self.data['login_date'] = pd.DatetimeIndex(self.data['_time']).date
            self.data['login_hour'] = pd.DatetimeIndex(self.data['_time']).hour
            return True
        except Exception as e:
            print('* ERROR IN CONVERTING INDEX TO DATETIME : ', e)
            return False

    def get_ip_switch_per(self, date, user, ip_data):
        self.row_no += 1
        switch_per = 0.0
        ip_data = LabelEncoder().fit_transform(ip_data)
        try:
            last_value = ip_data[0]
            switch_count = 0
            for d in ip_data[1:]:
                if d != last_value:
                    switch_count += 1
                last_value = d
            switch_per = switch_count / ip_data.size
        except:
            pass
        self.ip_switch_df.loc[self.row_no, 'login_date'] = date
        self.ip_switch_df.loc[self.row_no, 'user'] = user
        self.ip_switch_df.loc[self.row_no, 'ip_switch_per'] = switch_per

    def user_ip_switch(self):
        self.ip_switch_df = pd.DataFrame(columns=['login_date','user'])
        self.row_no = self.ip_switch_df.shape[0]
        for dt in self.login_date:
            for usr in self.users_list:
                self.get_ip_switch_per(dt, usr, \
                                       self.data.loc[(self.data['login_date']==dt) \
                                                     & (self.data['user']==usr), 'ipAddress']\
                                       .values)
        self.ip_switch_df.to_csv(os.path.join(ML_DIR, 'UsersIPSwitchRate_' + \
                                              self.timestamp + '.csv'), index=None)

    def get_outliers(self, data):
        if(data.shape[0] > 0):
            d = data['ipAddress'].values
            d = pd.get_dummies(d)
            data['outliers'] = IsolationForest(contamination='auto', behaviour='new')\
                                .fit_predict(d)
            if(data.loc[data['outliers']==1].shape[0] != 0):
                self.ip_based_outlier_df = self.ip_based_outlier_df\
                                        .append(data.loc[data['outliers']==-1,['_time','user','ipAddress']])

    def isp_check(self, ip_adr):
        response = self.rtree.search_best(ip_adr)
        if(response != None):
            if(ISP_NAME in response.data['isp']):
                return True
            else:
                return False
        return False

    def drop_ip_with_known_isp(self):
        print('Dropping IP with known ISP : ')
        ind_list = []
        for i in range(self.ip_based_outlier_df.shape[0]):
            if(self.isp_check(self.ip_based_outlier_df.loc[i, 'ipAddress'])):
                ind_list.append(i)
        self.ip_based_outlier_df = self.ip_based_outlier_df.drop(index=ind_list)

    def ipadr_based_outliers(self):
        self.ip_based_outlier_df = pd.DataFrame(columns=['_time', 'user', 'ipAddress'])
        for dt in tqdm(self.login_date):
            for usr in self.users_list:
                self.get_outliers(self.data.loc[(self.data['login_date']==dt) \
                                                & (self.data['user']==usr), \
                                                ['_time','user','ipAddress']])
        self.ip_based_outlier_df = self.ip_based_outlier_df.reset_index(drop=True)
        self.drop_ip_with_known_isp()
        self.ip_based_outlier_df.to_csv(os.path.join(ML_DIR, 'UsersIPAddressAnomaly_' + \
                                                     self.timestamp + '.csv'), index=None)

    def daily_user_login_patterning(self, df, count=0):
        date = df.loc[0,'login_date']
        for usr in tqdm(self.users_list):
            self.user_login_pattern_data.loc[count, 'date'] = date
            self.user_login_pattern_data.loc[count, 'user'] = usr
            zero_chk = 0
            for hour in range(24):
                status = df.loc[(df['user']==usr) & (df['login_hour']==hour), 'loginStatus'].values
                if(len(status) == 0):
                    self.user_login_pattern_data.loc[count, 'h'+str(hour)] = 0
                else:
                    if(status[0] == 'Success'):
                        self.user_login_pattern_data.loc[count, 'h'+str(hour)] = 1
                        zero_chk += 1
                    else:
                        self.user_login_pattern_data.loc[count, 'h'+str(hour)] = 0
            if(zero_chk > 0):
                count += 1
        return count

    def append_outlier_df(self, data):
        if(type(self.user_login_based_outliers) == type(None)):
            if(data.shape[0] != 0):
                self.user_login_based_outliers = data
        else:
            if(data.shape[0] != 0):
                self.user_login_based_outliers = self.user_login_based_outliers.append(data)

    def get_login_outlier(self, data):
        try:
            if(data.shape[0] > 2):
                isf_data = IsolationForest(random_state=8).fit_predict(data.drop(['user','date'], axis=1)\
                                                                   .reset_index(drop=True).values)
                data['outlier_tag'] = isf_data
                outlier_data = data.loc[data['outlier_tag']==-1, :]
                self.append_outlier_df(outlier_data[['user','date']])
        except:
            pass

    def user_login_anomaly(self):
        print('* User Login Patterning...')
        count = 0
        for dt in self.login_date:
            count = self.daily_user_login_patterning(self.data.loc[self.data['login_date']==dt, \
                                                           ['login_date','user',\
                                                            'loginStatus','login_hour']]\
                                             .reset_index(drop=True), count)
        self.user_login_based_outliers = None
        print('* Getting login outliers...')
        for usr in self.users_list:
            self.get_login_outlier(self.user_login_pattern_data.loc[self.user_login_pattern_data['user']==usr])
        self.user_login_based_outliers.to_csv(os.path.join(ML_DIR, 'UsersLoginAnomaly_' + \
                                                     self.timestamp + '.csv'), index=None)

    def perform_analysis(self, file_name):
        if self.read_csv_file(file_name):
            if self.verify_columns():
                if self.extract_date_hour():
                    try:
                        print('* Profiling...')
                        self.login_date = np.sort(self.data['login_date'].value_counts().index.values)
                        self.users_list = self.data['user'].value_counts().index.values
                        self.user_ip_switch()
                        self.ipadr_based_outliers()
                        user_login_pattern_cols = ['date', 'user'] + ['h'+str(i) for i in range(24)]
                        self.user_login_pattern_data = pd.DataFrame(columns=user_login_pattern_cols)
                        self.user_login_anomaly()
                    except Exception as e:
                        print('* ERROR IN PERFORMING ANALYSIS : ', e)
                        sys.exit(1)
            else:
                print('* Invalid columns found!')
                print('* Column names must be : ', O365_LOG_STD_COLS)
                sys.exit(1)


if __name__ == '__main__':
    print('* {}  v{}: O365'.format(__prog__, __version__))
    parser = argparse.ArgumentParser(description=__prog__, prog=__prog__)
    parser.add_argument('filename')
    args = parser.parse_args()

    if not os.access(RESOURCES_DIR, os.F_OK):
        print("* Error accessing '{}' folder! Exiting...!".format(RESOURCES_DIR))
        sys.exit(1)

    is_dirs(ML_DIR, OUTPUT_DIR)  # check if folders exist, else create them

    if args.filename:
        file_name = args.filename
        if not os.access(file_name, os.F_OK):
            print("* Error accessing '{}'! Exiting...!".format(file_name))
            sys.exit(1)
        oad = O365AnomalyDetector()
        oad.perform_analysis(file_name)
    else:
        print('* Example: ')
        print('* {} /path/to/log_file.csv'.format(__file__))
        sys.exit(1)
