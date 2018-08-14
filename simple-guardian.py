#!/usr/bin/env python3
import json
import os
import sqlite3
import sys
from queue import Queue
from threading import Thread, Lock

import requests
import time

import log_manipulator
from http_socket_client import HSocket

CONFIG_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), os.path.pardir, 'data'))
PROFILES_DIR = os.path.join(CONFIG_DIR, 'profiles')
CONFIG = {}
ONLINE_DATA = {'loggedIn': False}
PROFILES = {}
PROFILES_LOCK = Lock()
VERSION_TAG = "0.0"


class Database:
    queue_in = Queue()
    queue_out = Queue()
    db_lock = Lock()

    @staticmethod
    def init(file_path):
        class ThreadDatabase(Thread):
            def run(self):
                connection = sqlite3.connect(file_path)
                while AppRunning.is_running():
                    if not Database.queue_in.empty():
                        data = Database.queue_in.get()
                        if 'sql' in data:
                            db_respond = list(connection.execute(data['sql'], data['param']))
                        elif 'commit' in data:
                            connection.commit()
                            db_respond = True
                        else:
                            db_respond = None
                        Database.queue_out.put(db_respond)
                    AppRunning.sleep_while_running(0.1)

        ThreadDatabase().start()

    @staticmethod
    def execute(command, data=()):
        Database.db_lock.acquire()
        Database.queue_in.put({'sql': command, 'param': data})
        respond = Database.queue_out.get()
        Database.db_lock.release()
        return respond

    @staticmethod
    def json(command, table, data=()):
        columns = [column_data[1] for column_data in Database.execute("PRAGMA table_info(%s)" % table)]
        records = Database.execute(command, data)
        return [{columns[i]: value for i, value in enumerate(record)} for record in records]

    @staticmethod
    def commit():
        Database.db_lock.acquire()
        Database.queue_in.put({'commit': True})
        respond = Database.queue_out.get()
        Database.db_lock.release()
        return respond


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

    @staticmethod
    def sleep_while_running(seconds):
        while AppRunning.is_running() and seconds > 0:
            sleep = min(1, seconds)
            time.sleep(sleep)
            seconds -= sleep


class ThreadScanner(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        while AppRunning.is_running():
            print('Scanning')
            commit_db = False
            PROFILES_LOCK.acquire()
            profiles_copy = dict(PROFILES)
            PROFILES_LOCK.release()
            for profile, profile_data in profiles_copy.items():
                parser = log_manipulator.LogParser(profile_data['logFile'], profile_data['filters'])
                attacks = parser.parse_attacks(max_age=profile_data['scanRange'] * 2)
                known_attack_timestamps = []
                for ip, ip_attacks in attacks.items():
                    for i, attack_data in enumerate(ip_attacks):
                        while attack_data['TIMESTAMP'] in known_attack_timestamps:
                            attack_data['TIMESTAMP'] += 1
                        known_attack_timestamps.append(attack_data['TIMESTAMP'])
                        attacks[ip][i].update(attack_data)
                        if Database.execute('SELECT COUNT(*) FROM attacks WHERE ip = ? AND time = ? AND profile = ?',
                                            (ip, attack_data['TIMESTAMP'], profile))[0][0] == 0:
                            Database.execute('INSERT INTO `attacks`(`time`,`ip`,`data`,`profile`,`user`) '
                                             'VALUES (?,?,?,?,?);',
                                             (attack_data['TIMESTAMP'], ip, json.dumps(attack_data), profile,
                                              attack_data['USER'] if 'USER' in attack_data else None))
                            commit_db = True

                offenders = parser.get_habitual_offenders(profile_data['maxAttempts'], profile_data['scanRange'],
                                                          attacks=attacks)
                for offender_ip in offenders.keys():
                    if Database.execute('SELECT COUNT(*) FROM bans WHERE ip = ?',
                                        (offender_ip,))[0][0] == 0:
                        Database.execute('INSERT INTO `bans`(`time`,`ip`) VALUES (?,?);',
                                         (time.time(), offender_ip))
                        commit_db = True
            if commit_db:
                Database.commit()
            AppRunning.sleep_while_running(CONFIG['scanTime'])


def list_attacks(before=None, max_limit=None):
    sql = 'SELECT * FROM attacks'
    if before is not None:
        sql += ' WHERE id < ?'
    sql += ' ORDER BY id DESC'
    if max_limit is not None:
        sql += ' LIMIT ' + str(max_limit)
    return Database.json(sql, 'attacks', (before,) if before is not None else ())


def list_bans(before=None, max_limit=None):
    sql = 'SELECT * FROM bans'
    if before is not None:
        sql += ' WHERE id < ?'
    sql += ' ORDER BY id DESC'
    if max_limit is not None:
        sql += ' LIMIT ' + str(max_limit)
    bans = Database.json(sql, 'bans', (before,) if before is not None else ())
    for i, record in enumerate(bans):
        ip_attacks_count = Database.execute('SELECT COUNT(*) FROM attacks WHERE ip = ?', (record['ip'],))[0][0]
        bans[i]['attacksCount'] = ip_attacks_count
    print(bans)
    return bans


def load_profiles():
    PROFILES_LOCK.acquire()
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
    PROFILES_LOCK.release()


def login_with_server(url: str):
    try:
        server_data = requests.get(url).json()
    except requests.exceptions.ConnectionError:
        return False, 'cannot login, server is unreachable'
    except json.JSONDecodeError:
        return False, 'server returned unusable answer'
    ONLINE_DATA.update(server_data)
    ONLINE_DATA['loggedIn'] = True
    with open(os.path.join(CONFIG_DIR, 'server.json'), 'w') as f:
        json.dump(ONLINE_DATA, f, indent=1)
    return True, 'Logged in'


def init_online():
    socket = HSocket(ONLINE_DATA['server_url'], auto_connect=False)

    def connect():
        socket.emit('login', json.dumps({'uid': ONLINE_DATA['device_id'], 'secret': ONLINE_DATA['device_secret']}))

    def login(ok):
        if not ok:
            print('login with server seems expired, please fix this')
            return
        print('login ok')

    def get_attacks(data):
        attacks = list_attacks(data['before'], 100)
        socket.emit('attacks', json.dumps({'userSid': data['userSid'], 'attacks': attacks}))

    def get_bans(data):
        bans = list_bans(data['before'], 100)
        socket.emit('bans', json.dumps({'userSid': data['userSid'], 'bans': bans}))

    def config(data):
        PROFILES_LOCK.acquire()
        with open(os.path.join(PROFILES_DIR, 'online.json'), 'w') as f:
            json.dump(json.loads(data), f, indent=2)
        PROFILES_LOCK.release()
        load_profiles()

    socket.on('connect', connect)
    socket.on('login', login)
    socket.on('getAttacks', get_attacks)
    socket.on('getBans', get_bans)
    socket.on('config', config)
    socket.connect()


def main():
    # Load global configs
    with open(os.path.join(CONFIG_DIR, 'config.json'), 'r') as f:
        CONFIG.update(json.load(f))

    if 'login' in sys.argv:
        print(login_with_server(sys.argv[sys.argv.index('login') + 1])[1])
        exit()

    # Load online config
    if os.path.isfile(os.path.join(CONFIG_DIR, 'server.json')):
        with open(os.path.join(CONFIG_DIR, 'server.json'), 'r') as f:
            ONLINE_DATA.update(json.load(f))
        if ONLINE_DATA['loggedIn']:
            init_online()

    # Load all profiles
    print('Loading profiles')
    load_profiles()
    print('Profiles loaded')

    Database.init(os.path.join(CONFIG_DIR, 'db.db'))

    ThreadScanner().start()
    while True:
        try:
            input()
        except KeyboardInterrupt:
            AppRunning.set_running(False)


if __name__ == '__main__':
    main()
