import json
import os
import sys


def config_old_parse(old_config_path) -> dict:
    profiles = {}
    if not os.path.isfile(old_config_path):
        print('Error: config file "%s" does not exist' % old_config_path)
        exit(1)
    with open(old_config_path, 'rt') as f:
        lines = f.read().splitlines()
    config_part = "NOWHERE"
    profile = None
    for line in lines:
        if len(line) == 0 or line.startswith('#'):
            continue
        if line.startswith("--") and line.endswith('--'):
            config_part = line
            continue
        if config_part == "--PROFILES--":
            if line.startswith('[') and line.endswith(']'):
                profile = line[1:-1]
                profiles[profile] = dict()
                profiles[profile]['filters'] = list()
                continue
            if profile is None:
                continue
            if line.startswith('>>'):
                profiles[profile]['filters'].append(line[2:])
                continue
            if '=' not in line:
                continue
            property_name, property_value = line.split('=', 1)
            if property_name == 'LogFile':
                property_name = "logFile"
            try:
                profiles[profile][property_name] = int(property_value)
            except ValueError:
                profiles[profile][property_name] = property_value
            continue
    return profiles


if __name__ == '__main__':
    try:
        file_from = sys.argv[1]
        file_to = sys.argv[2]
    except IndexError:
        print('usage: script.py old_config.conf new_config.json')
        exit(1)
    # noinspection PyUnboundLocalVariable
    with open(file_to, 'w') as f:
        # noinspection PyUnboundLocalVariable
        json.dump(config_old_parse(file_from), f, indent=2)
