import re
import time
from datetime import datetime


def remove_whitespaces(string: str):
    while string[0].isspace():
        string = string[1:]
    while string[-1].isspace():
        string = string[:-1]
    return string


class LogParser:
    def __init__(self, file_log: str, rules: list, service_name=None):
        self.file_log = file_log
        self.rules = [rule if type(rule) == Rule else Rule(rule, service_name) for rule in rules]

    def parse_attacks(self, max_age=None) -> dict:
        attacks = {}
        with open(self.file_log, 'r') as f:
            log_lines = f.read().splitlines()
        for log_line in log_lines:
            for rule in self.rules:
                variables = rule.get_variables(log_line)
                if variables is not None:
                    if max_age is not None and time.time() - max_age > variables['TIMESTAMP']:
                        break
                    attacker_ip = variables['IP']
                    del variables['IP']
                    item = attacks.get(attacker_ip, [])
                    item.append(variables)
                    attacks[attacker_ip] = item
                    break

        return attacks

    def get_habitual_offenders(self, min_attack_attempts: int, attack_attempts_time: int, max_age=None) -> dict:
        attacks = self.parse_attacks(max_age)
        habitual_offenders = {}

        for ip, attack_list in attacks.items():
            for attack in attack_list:
                attacks_in_time_range = []
                for attack2 in attack_list:
                    attack_time_delta = attack2['TIMESTAMP'] - attack['TIMESTAMP']
                    if 0 <= attack_time_delta <= attack_attempts_time:
                        attacks_in_time_range.append(attack2)
                        if len(attacks_in_time_range) > min_attack_attempts:
                            break
                if len(attacks_in_time_range) >= min_attack_attempts:
                    habitual_offenders[ip] = attack_list

        return habitual_offenders


class Rule:
    def __init__(self, filter_string: str, service_name=None):
        self.__service_name = service_name
        self.__rule_variables = re.findall("%.*?%", filter_string)

        # Generate regex for rule detection
        self.__rule_regex = filter_string
        for reserved_char in list("\\+*?^$.[]{}()|/"):  # escape reserved regex characters
            self.__rule_regex = self.__rule_regex.replace(reserved_char, '\\' + reserved_char)
        for variable in self.__rule_variables:  # replace all variables with any regex characters
            self.__rule_regex = self.__rule_regex.replace(variable, '(.+?)')
        if self.__rule_regex.endswith('?)'):  # disable lazy search for last variables so they are found whole
            self.__rule_regex = self.__rule_regex[:-2] + ')'

        # Remove %'s from variable names
        self.__rule_variables = [var[1:-1] for var in self.__rule_variables]

    def test(self, log_line: str) -> bool:
        return True if re.match(self.__rule_regex, log_line) else False

    def get_variables(self, log_line):
        data = {}

        # Parse all variables from log line
        variable_search = re.match(self.__rule_regex, log_line)
        if not variable_search:  # this rule is not for this line
            return None
        # noinspection PyTypeChecker
        for i, variable in enumerate(self.__rule_variables):
            data[variable] = remove_whitespaces(variable_search.group(i + 1))

        if self.__service_name is not None:
            data['SERVICE'] = self.__service_name

        date_format = '%Y %b %d %H:%M:%S'
        date_string = None
        if 'D:M' in data and 'D:D' in data and 'TIME' in data:
            date_string = '%s %s %s %s' % (datetime.now().strftime('%Y'), data['D:M'],
                                           data['D:D'], data['TIME'])
        elif 'D:M' in data and 'D:D' in data:
            date_string = '%s %s %s 00:00:00' % (datetime.now().strftime('%Y'), data['D:M'], data['D:D'])
        elif 'TIME' in data:
            # noinspection PyTypeChecker
            date_string = datetime.now().strftime('%Y %b %d') + ' ' + data['TIME']

        data['TIMESTAMP'] = time.time() if date_string is None else \
            time.mktime(datetime.strptime(date_string, date_format).timetuple())
        return data


if __name__ == '__main__':
    all_rules = ["%D:M% %D:D% %TIME% %IP% attacked on user %USER%"]
    file = 'auth.log'

    parser = LogParser(file, all_rules)
    offenders = parser.get_habitual_offenders(3, 100000)
    for off_ip, off_attacks in offenders.items():
        print(off_ip + ':', off_attacks)
