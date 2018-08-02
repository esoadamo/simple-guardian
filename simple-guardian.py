#!/usr/bin/env python3
import json
import os
import sqlite3
import time
from threading import Thread

import log_manipulator

CONFIG_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), os.path.pardir, 'data'))
PROFILES_DIR = os.path.join(CONFIG_DIR, 'profiles')
CONFIG = {}
PROFILES = {}


class AppRunning:
    app_running = [True]

    @staticmethod
    def is_running() -> bool:
        return len(AppRunning.app_running) > 0

    @staticmethod
    def set_running(val: bool):
        if val:
            AppRunning.app_running.append(True)
        else:
            AppRunning.app_running.clear()


class ThreadScanner(Thread):
    def __init__(self):
        Thread.__init__(self)

    @staticmethod
    def sleep_while_running(seconds):
        while AppRunning.is_running() and seconds > 0:
            sleep = min(1, seconds)
            time.sleep(sleep)
            seconds -= sleep

    def run(self):
        file_database = os.path.join(CONFIG_DIR, 'db.db')

        self.db = sqlite3.connect(file_database)

        while AppRunning.is_running():
            print('Scanning')
            commit_db = False
            for profile, profile_data in PROFILES.items():
                parser = log_manipulator.LogParser(profile_data['logFile'], profile_data['filters'])
                attacks = parser.parse_attacks(max_age=profile_data['scanRange'] * 2)
                known_attack_timestamps = []
                for ip, ip_attacks in attacks.items():
                    for i, attack_data in enumerate(ip_attacks):
                        while attack_data['TIMESTAMP'] in known_attack_timestamps:
                            attack_data['TIMESTAMP'] += 1
                        known_attack_timestamps.append(attack_data['TIMESTAMP'])
                        attacks[ip][i].update(attack_data)
                        if list(self.db.execute('SELECT COUNT(*) FROM attacks WHERE ip = ? AND time = ?',
                                                (ip, attack_data['TIMESTAMP'])))[0][0] == 0:
                            self.db.execute('INSERT INTO `attacks`(`time`,`ip`,`data`) VALUES (?,?,?);',
                                            (attack_data['TIMESTAMP'], ip, json.dumps(attack_data)))
                            commit_db = True
            if commit_db:
                self.db.commit()
            ThreadScanner.sleep_while_running(CONFIG['scanTime'])


def main():
    # Load global configs
    with open(os.path.join(CONFIG_DIR, 'config.json'), 'r') as f:
        CONFIG.update(json.load(f))

    # Load all profiles
    print('Loading profiles')
    if not os.path.exists(PROFILES_DIR):
        os.makedirs(PROFILES_DIR)
    else:
        for file_profile in os.listdir(PROFILES_DIR):
            if not file_profile.endswith('.json'):
                continue
            file_profile = os.path.join(PROFILES_DIR, file_profile)
            with open(file_profile, 'r') as f:
                try:
                    loaded_profiles = json.load(f)
                except json.decoder.JSONDecodeError:
                    print('Invalid profile - not loading (%s)' % file_profile)
                    continue
                for profile, profile_data in loaded_profiles.items():
                    if profile not in PROFILES:
                        PROFILES[profile] = dict(CONFIG['defaults'])
                    PROFILES[profile].update(profile_data)
    print('Profiles loaded')

    ThreadScanner().start()
    while True:
        try:
            input()
        except KeyboardInterrupt:
            AppRunning.set_running(False)


if __name__ == '__main__':
    main()
