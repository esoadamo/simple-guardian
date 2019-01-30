import re
import time
from datetime import datetime
from typing import List


class LogParser:
    """
    Class for parsing information about attacks from log files
    """

    def __init__(self, file_log, rules, service_name=None):  # type: (str, List[str], str) -> None
        """
        Initialize the log parser
        :param file_log: path to the file with logs
        :param rules: list of string filters/rules
        :param service_name: optional name of the service. If not specified then found attacks are not assigned to any
        service
        """
        self.file_log = file_log
        self.rules = [rule if type(rule) == Rule else Rule(rule, service_name) for rule in rules]

    def parse_attacks(self, max_age=None):  # type: (float) -> dict
        """
        Parses the attacks from log file and returns them
        :param max_age: optional, in seconds. If attack is older as this then it is ignored
        :return: dictionary. Key is the IP that attacked and value is list of dictionaries with data about every attack
        """
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

    def get_habitual_offenders(self, min_attack_attempts, attack_attempts_time, max_age=None, attacks=None):
        # type: (int, int, int, dict) -> dict
        """
        Finds IPs that had performed more than allowed number of attacks in specified time range
        :param min_attack_attempts: minimum allowed number of attacks in time range to be included
        :param attack_attempts_time:  the time range in which all of the attacks must have occurred in seconds
        :param max_age: optional, in seconds. If attack is older as this then it is ignored
        :param attacks: optional. If None, then the value of self.parse_attacks(max_age) is used
        :return: dictionary. Key is the IP that attacked more or equal than min_attack_attempts times and
        value is list of dictionaries with data about every attack in specified time range
        """
        attacks = self.parse_attacks(max_age) if attacks is None else attacks
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
    """
    Rule or filter that can be tested on a line from config line. If this rule/filter fits, than it can parse
    variables from that line
    """

    def __init__(self, filter_string: str, service_name=None):
        """
        Initializes this rule/filter
        :param filter_string: string representation of this rule/filter with all variables stated as %VAR_NAME%
        :param service_name: optional name of the service. If not specified then found attacks are not assigned to any
        service
        """
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
        """
        Test this Rule against a line from log file if it fits
        :param log_line: line from a log file
        :return: True if it fits, False if this rule cannot be applied to this line
        """
        return True if re.match(self.__rule_regex, log_line) else False

    def get_variables(self, log_line):  # type: (str) -> dict or None
        """
        Parses variables from log line that fits this rule
        :param log_line: line from a log file
        :return: None if this rule cannot be applied to this line, otherwise returns a dictionary with parsed variables
        from this line
        """
        data = {}

        # Parse all variables from log line
        variable_search = re.match(self.__rule_regex, log_line)
        if not variable_search:  # this rule is not for this line
            return None
        # noinspection PyTypeChecker
        for i, variable in enumerate(self.__rule_variables):
            data[variable] = variable_search.group(i + 1).strip()

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


# If launched directly, perform a quick proof of work in file debug.log
if __name__ == '__main__':
    all_rules = ["%D:M% %D:D% %TIME% %IP% attacked on user %USER%"]
    file = 'debug.log'

    parser = LogParser(file, all_rules)
    offenders = parser.get_habitual_offenders(3, 100000)
    for off_ip, off_attacks in offenders.items():
        print(off_ip + ':', off_attacks)
