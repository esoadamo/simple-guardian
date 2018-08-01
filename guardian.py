import time
from datetime import datetime


class LogParser:
    def __init__(self, file_log: str, rules: list):
        self.file_log = file_log
        self.rules = rules

    def parse_attacks(self) -> dict:
        attacks = {}
        with open(self.file_log, 'r') as f:
            log_lines = f.read().splitlines()
        for log_line in log_lines:
            for rule in self.rules:
                filter_result = LogParser.test_filter_on_line(rule, log_line)
                if filter_result:
                    item = attacks.get(filter_result['IP'], [])
                    item.append(filter_result['TIMESTAMP'])
                    attacks[filter_result['IP']] = item
                    break

        return attacks

    @staticmethod
    def test_filter_on_line(filter_line: str, log_line: str, min_time=None):
        """
        Tests a filter on some line

        :param filter_line: filter used on the log_line
        :param log_line: log_line itself
        :param min_time: minimal time (time.time) that still counts as relevant attack
        :return: dictionary with found variables if filter succeed, otherwise False
        """
        while '  ' in log_line:
            log_line = log_line.replace('  ', ' ')
        ls = log_line.split(' ')
        fs = filter_line.split(' ')

        filter_vars = {
            'IP': None,
            'TIMESTAMP': None,
            'USER': None
        }
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
        filter_check = filter_line
        for k, v in filter_vars.items():
            if v is None:
                continue
            # noinspection PyTypeChecker
            filter_check = filter_check.replace('%' + k + '%', v)
        if not filter_check == log_line:
            return False

        # check if the log is not old
        date_format = '%Y %b %d %H:%M:%S'
        if 'D:M' in filter_vars and 'D:D' in filter_vars and 'TIME' in filter_vars:
            date_string = '%s %s %s %s' % (datetime.now().strftime('%Y'), filter_vars['D:M'],
                                           filter_vars['D:D'], filter_vars['TIME'])
        elif 'D:M' in filter_vars and 'D:D' in filter_vars:
            date_string = '%s %s %s 00:00:00' % (datetime.now().strftime('%Y'), filter_vars['D:M'], filter_vars['D:D'])
        elif 'TIME' in filter_vars:
            # noinspection PyTypeChecker
            date_string = datetime.now().strftime('%Y %b %d') + ' ' + filter_vars['TIME']
        else:
            filter_vars['TIMESTAMP'] = time.time()  # we do not know the attack time, so we suggest it happened now
            return filter_vars

        attack_time = time.mktime(datetime.strptime(date_string, date_format).timetuple())
        if min_time is not None and attack_time < min_time:
            return False

        filter_vars['TIMESTAMP'] = attack_time

        return filter_vars


if __name__ == '__main__':
    all_rules = [
        "%D:M% %D:D% %TIME% %HOSTNAME% sshd[%PID%]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=%IP% user=%USER%",
        "%D:M% %D:D% %TIME% %HOSTNAME% sshd[%PID%]: error: PAM: Authentication failure for %USER% from %IP%",
        "%D:M% %D:D% %TIME% %HOSTNAME% sshd[%PID%]: Postponed keyboard-interactive for invalid user %USER% from %IP% port %PORT% ssh2 [preauth]",
        "%D:M% %D:D% %TIME% %HOSTNAME% sshd[%PID%]: Failed keyboard-interactive/pam for invalid user %USER% from %IP% port %PORT% ssh2",
        "%D:M% %D:D% %TIME% %HOSTNAME% sshd[%PID%]: error: maximum authentication attempts exceeded for invalid user %USER% from %IP% port %PORT% ssh2 [preauth]"]
    file = 'auth.log'
    parser = LogParser(file, all_rules)
    print(len(parser.parse_attacks()))
