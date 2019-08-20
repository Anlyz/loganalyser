"""
Copyright© Anlyz Inc.,
Log analyser analyses csv logs with a particular format to provide security analytics.
Config: This is the configuration file for all the log analysers
Version: 1.1
Changelog:
    v0.1        Initial Framework
    v0.9        slice window (in seconds)
    v1.0        command line options
    v1.1        Final Release
"""
import os

__prog__ = 'Security Log Analytics'
__authors__ = ['sg', 'pk']
__license__ = "MIT License"
__version__ = 1.1


DATA_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "data")

# ML/DL models folder
ML_DIR = os.path.join(DATA_DIR, "ml")

# Output folder. Folder where the output will be placed
OUTPUT_DIR = os.path.join(DATA_DIR, 'output')

# Resources folder, where geoip_db, joblib etc exists
RESOURCES_DIR = os.path.join(DATA_DIR, 'resources')

# GeoIP database location
GEOLITE_DB = os.path.join(RESOURCES_DIR, 'GeoLite2-City/GeoLite2-City.mmdb')

# URL FOR FETCHING UPDATED IP-ASN and ASN-ISP DATA AND IP-ISP database location
IP_ASN_URL = 'http://thyme.apnic.net/current/data-raw-table'
ASN_ISP_URL = 'http://thyme.apnic.net/current/data-used-autnums'
IP_ISP_RTREE_JOBLIB = os.path.join(RESOURCES_DIR, 'ip_isp_rtree.joblib')

# Blacklisted IP TRIE Joblib and output file
BLACKLISTED_IP_TRIE_JOBLIB = os.path.join(RESOURCES_DIR, 'blacklisted_ip_trie.joblib')
BLACKLISTED_IP_URL = 'https://myip.ms/files/blacklist/general/full_blacklist_database.zip'

# The Log files should be in a CSV format and must have standard columns
# The below of the standard column format that the log file must have
# Should this change, change the LOG_STD_COLS down below here, but be sure
# that the below fields/columns are a must to perform the analytics/profiling
FIREWALL_LOG_STD_COLS = {'_time', 'host', 'action', 'dest_ip', 'dest_port', 'src_ip'}
O365_LOG_STD_COLS = {'_time', 'deviceInformation', 'ipAddress', 'user', 'location.country', 'location.city', 'app', 'loginStatus'}

# Time window bucket:
# 's' is for seconds and must always end with 's'
# eg: 60s, 120s, 3600s, etc...
WINDOW_SLICE = '60s'

# CONFIGURING ISP NAME OF THE ENTERPRISE
ISP_NAME = 'NETAPP'

if __name__ == '__main__':
    print('*** Cannot execute config file! ***')
