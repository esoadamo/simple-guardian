#!/usr/bin/python3
"""
MIT License

Copyright (c) 2017 Adam Hlaváček

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import os
import sys
from datetime import datetime
import time
from subprocess import call, PIPE

version = "Aachenosaurus"

CONFIG_PATH = __file__[:-len(os.path.basename(__file__))] + 'guardian.conf'

PROFILES = dict()
GLOBAL_CONFIG = dict()


def config_parse():
    """
    Parses config from CONFIG_PATH file
    :return: None, everything is saved into global PROFILES dict
    """
    with open(CONFIG_PATH, 'rt') as f:
        lines = f.read().splitlines()
    config_part = "NOWHERE"
    profile = None
    for line in lines:
        if len(line) == 0 or line.startswith('#'):
            continue
        if line.startswith("--") and line.endswith('--'):
            config_part = line
            continue
        if config_part == "--GLOBAL-CONFIG--":
            if '=' not in line:
                continue
            s = line.split('=')
            try:
                GLOBAL_CONFIG[s[0]] = int(s[1])
            except ValueError:
                GLOBAL_CONFIG[s[0]] = s[1]
            continue
        if config_part == "--PROFILES--":
            if line.startswith('[') and line.endswith(']'):
                profile = line[1:-1]
                PROFILES[profile] = dict()
                PROFILES[profile]['config'] = dict()
                PROFILES[profile]['filters'] = list()
                continue
            if profile is None:
                continue
            if line.startswith('>>'):
                PROFILES[profile]['filters'].append(line[2:])
                continue
            if '=' not in line:
                continue
            s = line.split('=')
            try:
                PROFILES[profile]['config'][s[0]] = int(s[1])
            except ValueError:
                PROFILES[profile]['config'][s[0]] = s[1]
            continue
        print('WARNING: Config failed on line "%s"' % line)


def test_filter(filter_str: str, line: str, min_time=None):
    """
    Tests a filter on some line
    
    :param filter_str: filter used on the line
    :param line: line itself
    :param min_time: minimal time (time.time) that still counts as relevant attack
    :return: dictionary with found variables if filter succeed, otherwise False
    """
    while '  ' in line:
        line = line.replace('  ', ' ')
    ls = line.split(' ')
    fs = filter_str.split(' ')

    filter_vars = dict()
    if len(ls) != len(fs):
        return False

    for i in range(len(ls)):
        if fs[i].count('%') == 2:
            var_start = fs[i].index('%')
            var_stop = -1 * (len(fs[i]) - fs[i].index('%', var_start + 1))
            var_name = fs[i][var_start + 1:var_stop]
            var_val_stop = var_stop + 1 if var_stop < -1 else len(ls[i])
            var_val = ls[i][var_start:var_val_stop]
            filter_vars[var_name] = var_val
    filter_check = filter_str
    for k, v in filter_vars.items():
        filter_check = filter_check.replace('%' + k + '%', v)
    if not filter_check == line:
        return False

    if min_time is None:
        return filter_vars

    # check if the log is not old
    date_format = '%Y %b %d %H:%M:%S'
    if 'D:M' in filter_vars and 'D:D' in filter_vars and 'TIME' in filter_vars:
        date_string = '%s %s %s %s' % (datetime.now().strftime('%Y'), filter_vars['D:M'],
                                       filter_vars['D:D'], filter_vars['TIME'])
    elif 'D:M' in filter_vars and 'D:D' in filter_vars:
        date_string = '%s %s %s 00:00:00' % (datetime.now().strftime('%Y'), filter_vars['D:M'], filter_vars['D:D'])
    elif 'TIME' in filter_vars:
        date_string = datetime.now().strftime('%Y %b %d') + ' ' + filter_vars['TIME']
    else:
        return filter_vars

    attack_time = time.mktime(datetime.strptime(date_string, date_format).timetuple())
    if attack_time < min_time:
        return False

    return filter_vars


def main():
    config_parse()

    try:
        if sys.argv[1] == '-h' or sys.argv[1] == '--help' or sys.argv[1] == '/?':
            print('Usage: ip-banner.py [max-relevant-time=86400] [--test-run] [--list-attack-only]')
            print('max-relevant-time: number of seconds until log entries are supposed to be old, set to -1 to disable')
            print('--test-run: says not send emails or apply blocking or write to any file. Just print to console.')
            print('--list-attacks-only: just list attacks and exit')
            print('--no-email: disable sending email at the end')
            exit(0)
        max_age = int(sys.argv[1])
    except (ValueError, IndexError):
        max_age = 24 * 3600  # one day

    test_run = '--test-run' in sys.argv
    list_attacks_only = '--list-attacks-only' in sys.argv
    no_mail = '--no-email' in sys.argv

    min_relevant_time = time.time() - max_age

    # Put all filters related to the same file on one place
    dict_file_filters = dict()  # file: list of filters
    for profile in PROFILES:
        if PROFILES[profile]['config']['LogFile'] not in dict_file_filters:
            dict_file_filters[PROFILES[profile]['config']['LogFile']] = list()
        dict_file_filters[PROFILES[profile]['config']['LogFile']].extend((profile, PROFILES[profile]['filters']))

    # Search all files for attacks
    vars_found = list()  # list of dictionaries with data about attack
    print('[Searching for attacks]')
    for log_file, filters in dict_file_filters.items():   # filters is tuple: profile_name, filter_string
        with open(log_file, 'rt') as f:
            lines = f.read().splitlines()
        for line in lines:
            for filter_data in filters[1]:
                filter_vars = test_filter(filter_data, line, min_relevant_time)
                if filter_vars:
                    filter_vars['PROFILE'] = filters[0]
                    vars_found.append(filter_vars)
                    print('#%d %s -> %s (%s)' % (len(vars_found),
                                                 filter_vars['IP'] if 'IP' in filter_vars else 'unknown',
                                                 filter_vars['USER'] if 'USER' in filter_vars else 'unknown',
                                                 filter_vars['PROFILE']))
                    break

    if list_attacks_only:
        exit(0)

    # Examine who to block
    if 'MaxAttempts' not in GLOBAL_CONFIG:
        print('Error: MaxAttempts not found in global config')
        exit(1)
    if 'BlockCommand' not in GLOBAL_CONFIG:
        print('Error: BlockCommand not found in global config')
        exit(1)
    dict_ip_attempts = dict()
    print('[Blocked IPs]')
    for filter_vars in vars_found:
        if 'IP' in filter_vars:
            dict_ip_attempts[filter_vars['IP']] = dict_ip_attempts.get(filter_vars['IP'], 0) + 1
    blocked_ips = set()
    for ip, attempts_count in dict_ip_attempts.items():
        if attempts_count < GLOBAL_CONFIG['MaxAttempts']:
            continue
        blocked_ips.add(ip)
        print('#%d %s <- %d attempts' % (len(blocked_ips), ip, attempts_count))
        command = GLOBAL_CONFIG['BlockCommand'].replace('%IP%', ip)
        if test_run:
            print('TEST RUN: (not) executing "%s"' % command)
        else:
            call(command, shell=True, stderr=PIPE, stdout=PIPE)

    # Save list with blocked IPs
    if 'SaveBlocked' in GLOBAL_CONFIG and len(GLOBAL_CONFIG['SaveBlocked']) > 0:
        blocked_ips_all = set().union(blocked_ips)
        if test_run:
            print('TEST RUN: (not) saving list of blocked IPs into %s' % GLOBAL_CONFIG['SaveBlocked'])
        else:
            with open(GLOBAL_CONFIG['SaveBlocked'], 'a+') as f:
                lines = f.read().splitlines()
                for line in lines:
                    if len(line) == '0':
                        continue
                    blocked_ips_all.add(line)
                if len(blocked_ips_all) != len(blocked_ips):  # Save only if file was modified
                    f.seek(0)
                    f.write('\n'.join(blocked_ips_all))
                    f.truncate()

    # Send info mail
    if no_mail\
            or 'MailCommand' not in GLOBAL_CONFIG\
            or 'SendMail' not in GLOBAL_CONFIG\
            or len(GLOBAL_CONFIG['MailCommand']) == 0:
        exit(0)

    mail_subject = "Today blocked IPs (%d) and attacks (%d)" % (len(blocked_ips), len(vars_found))
    mail_lines = list()

    mail_lines.append('[Blocked IPs]')
    for ip, attempts_count in dict_ip_attempts.items():
        if attempts_count < GLOBAL_CONFIG['MaxAttempts']:
            continue
        mail_lines.append('%s <- %d attempts' % (ip, attempts_count))
    mail_lines.append('[All attacks]')
    for filter_vars in vars_found:
        mail_lines.append('%s -> %s' % (filter_vars['IP'] if 'IP' in filter_vars else 'unknown',
                                        filter_vars['USER'] if 'USER' in filter_vars else 'unknown'))

    command = GLOBAL_CONFIG['MailCommand'].replace('%SUBJECT%', mail_subject)\
        .replace('%TARGET_MAIL%', GLOBAL_CONFIG['SendMail'])\
        .replace('%MESSAGE%', '\n'.join(mail_lines))
    if test_run:
        print('TEST RUN: (not) executing "%s"' % command)
    else:
        call(command, shell=True, stderr=PIPE, stdout=PIPE)

if __name__ == '__main__':
    main()
