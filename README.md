# Log Analyzer
Log Analyzer can be used to analyze different logs.
Logs currently supported are:
- O365 Logs
- Firewall Logs

#### Requirements
- Python 3

#### Installing RE2
- macOS
```bash
brew install re2
```
- Debian based
```bash
apt install libre2-3
```

#### Logs Structure Requirements
Log should be in csv format.
- Firewall Logs Columns
```bash
_time, host, action, dest_ip, dest_port, src_ip
```
- O365 Logs Columns
```bash
_time, deviceInformation, ipAddress, user, location.country, location.city, app, loginStatus
```

#### Installation
```bash
cd /path/to/loganalyser/
mkvirtualenv loganalyser --python=$(which python3)
setvirtualenvproject
```
##### Requirements installation
```bash
pip install -r requirements.txt
```

#### Configuration
- Config File: All settings are present in the config file. The config file can be edited to change default values. You can also pass command line arguments to change other parameters w.r.t analysis.

#### Execute & get the output
- Firewall Examples:
```bash
./firewall_log_analysis.py /path/to/filewall_log.csv
```
- O365 Eamples:
```bash
./o365_log_analysis.py /path/to/O365_log.csv
./o365_anomalies.py /path/to/O365_log.csv
```

#### Manual update for blacklisted IP Trie :
To update the Blacklisted IP Trie manually:
```bash
./get_blacklist_ip_trie.py
```

#### Manual update for IP to ISP Radix Tree :
To update the IP to ISP Radix Tree manually:
```bash
./build_updated_ip_to_isp_db.py
```

### Output Files
Location : Output Directory (loganalyser/data/output/)
- SuccessFailureLoginCount_....csv => For every user total count of successful logins and failed logins.
- MaxLoginFailureByEachUserInWindowedTimeFrame_....csv => Maximum Count of login failures for each user in specified time window.
- FailedLoginFromDifferentOS_....csv => Maximum Count of login failures for every user from different Operating Systems in specified time window.
- FailedLoginFromDifferentIP_....csv => Maximum Count of login failures for every user from different IPs in specified time window. Also included detail of maliciousness of IP.
- BlockedTrafficForEachDestinationIP_....csv => Maximum count of blocked traffic for every destination IP on different destination Ports in specified time window. Also included detail of maliciousness of IP and geo IP locations for most of the destination IPs.
- BlockedTrafficForEachSourceIP_....csv => Maximum count of blocked traffic from different source IPs to different destination IPs on different destination Ports in specified time window. Also included detail of maliciousness of IP and geo IP locations for most of the IPs.

Location : ML Output Directory (loganalyser/data/ml/)
- UsersIPAddressAnomaly_....csv => IP Address anomaly for each user on a daily basis.
- UsersIPSwitchRate_....csv => Rate of IP switch per user per day (between 0 to 1 with 0 meaning no switch and 1 meaning all IPs used in a day are different)
- UsersLoginAnomaly_....csv => Users login patterning hour wise per day and finding deviations in the pattern and saving the username along with the date when deviation was found in this csv file.
