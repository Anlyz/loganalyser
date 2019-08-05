"""
Copyright© Anlyz Inc.,
Log analyser analyses csv logs with a particular format to provide security analytics.
Utils: This is the util/helper file with common functions
Version: 1.1
Changelog:
    v0.1        Initial Framework
    v0.9        slice window (in seconds)
    v1.0        command line options
    v1.1        Final Release
"""
import os
import ipaddress


def is_dirs(*args):
    """
    Validate the given directories exists. If the given directories
    do not exist, then creates them.
    :param args: dir1, dir2, dir3, etc, ...
    :return: None. (creates directories if they do not exist)
    """
    for arg in args:
        if not os.access(arg, os.F_OK):
            print("*** {} does not exist; creating...".format(arg))
            os.makedirs(arg)


def check_window_slice(window_slice):
    """
    Validate WINDOW_SLICE to make sure that it has 's' @ the ending
    If not add 's' @ the ending
    :param window_slice:
    :return:
    """
    if str(window_slice).isnumeric():
        window_slice = '{}s'.format(window_slice)
    return window_slice


def is_ip_private(ip_address):
    """
    Check if the given IP address is Private IP or not
    :param ip_address:
    :return: True if Private IP
    """
    return ipaddress.ip_address(ip_address).is_private


if __name__ == '__main__':
    print('*** Cannot execute util file! ***')
