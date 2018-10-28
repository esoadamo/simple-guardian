#!/usr/bin/env python3
import json
import os
import sqlite3
import subprocess
import sys
import time
from datetime import date
from queue import Queue
from subprocess import Popen
from threading import Thread, Lock

import requests

import github_updater
import log_manipulator
from http_socket_client import HSocket

# the Runner - this is what enables us to restart server during runtime
if __name__ == '__main__':
    """
    If not slave, run this script again as a slave
    When slave script ends, check if his return code is 42.
    If so, restart the script again, otherwise exit program with given exitcode

    Must be on start to keep memory usage as low as possible
    """
    if sys.argv[-1] != 'SLAVE':
        process = None
        try:
            while True:
                stderr = None
                process = Popen([sys.executable] + sys.argv + ['SLAVE'])
                process.communicate()
                process.wait()
                r = process.returncode
                if r == 42:
                    continue
                break
            exit(r)
        except KeyboardInterrupt:
            if process is not None:
                process.kill()
            print('^C received, shutting down master process')
            exit(0)
    del sys.argv[-1]
# End of the Runner

CONFIG_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), os.path.pardir, 'data'))
PROFILES_DIR = os.path.join(CONFIG_DIR, 'profiles')
CONFIG = {}
ONLINE_DATA = {'loggedIn': False}
PROFILES = {}
PROFILES_LOCK = Lock()
VERSION_TAG = "0.98"


class Database:
    queue_in = Queue()
    queue_out = Queue()
    db_lock = Lock()

    @staticmethod
    def init(file_path):
        class ThreadDatabase(Thread):
            def run(self):
                connection = sqlite3.connect(file_path)
                connection.execute('CREATE TABLE IF NOT EXISTS "bans" ('
                                   '`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
                                   '`time` INTEGER NOT NULL,'
                                   '`ip` TEXT NOT NULL);')
                connection.execute('CREATE TABLE IF NOT EXISTS "attacks" ('
                                   '`id` INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,'
                                   '`time` INTEGER NOT NULL,'
                                   '`ip` TEXT NOT NULL,'
                                   '`profile` TEXT NOT NULL,'
                                   '`user` TEXT,'
                                   '`data` INTEGER NOT NULL);')
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
    def exit(exit_code):
        AppRunning.set_running(False)
        exit(exit_code)

    @staticmethod
    def sleep_while_running(seconds):
        while AppRunning.is_running() and seconds > 0:
            sleep = min(1, seconds)
            time.sleep(sleep)
            seconds -= sleep


class IPBlocker:
    block_command_path = './blocker'

    @staticmethod
    def list_blocked_ips() -> set:
        return {record[0] for record in Database.execute('SELECT ip FROM bans')}

    @staticmethod
    def ip_is_blocked(ip):
        return Database.execute('SELECT COUNT(*) FROM bans WHERE ip = ?', (ip,))[0][0] != 0

    @classmethod
    def block_all_banned(cls):
        [cls.block(ip) for ip in cls.list_blocked_ips()]

    @classmethod
    def block(cls, ip, commit_db=True):
        if cls.ip_is_blocked(ip):
            return False
        subprocess.run([cls.block_command_path, 'block', ip])
        Database.execute('INSERT INTO `bans`(`time`,`ip`) VALUES (?,?);', (time.time(), ip))
        if commit_db:
            Database.commit()
        return True

    @classmethod
    def unblock(cls, ip, commit_db=True):
        if not cls.ip_is_blocked(ip):
            return False
        subprocess.run([cls.block_command_path, 'unblock', ip])
        Database.execute('DELETE FROM bans WHERE ip = ?', (ip,))
        if commit_db:
            Database.commit()
        return True


class ThreadScanner(Thread):
    def run(self):
        while AppRunning.is_running():
            print('scanning for attacks')
            commit_db = False
            PROFILES_LOCK.acquire()
            profiles_copy = dict(PROFILES)
            PROFILES_LOCK.release()
            for profile, profile_data in profiles_copy.items():
                parser = log_manipulator.LogParser(profile_data['logFile'], profile_data['filters'])
                try:
                    attacks = parser.parse_attacks(max_age=profile_data['scanRange'] * 2)
                except FileNotFoundError:
                    continue
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
                    if IPBlocker.block(offender_ip, commit_db=False):
                        commit_db = True
            if commit_db:
                Database.commit()
            print('scanning for attacks completed')
            AppRunning.sleep_while_running(CONFIG['scanTime'])


class Updater:
    _updater = None

    @staticmethod
    def init():
        Updater._updater = github_updater.GithubUpdater(CONFIG['updater']['githubOwner'],
                                                        CONFIG['updater']['githubRepo'])

    @staticmethod
    def update_available():
        return VERSION_TAG != Updater._updater.get_latest_release_tag()

    @staticmethod
    def get_latest_name() -> str:
        return Updater._updater.get_latest_release_tag()

    @staticmethod
    def update(restart=True):
        print('starting update')
        this_directory = os.path.abspath(os.path.join(os.path.abspath(__file__), os.path.pardir))
        Updater._updater.get_and_extract_newest_release_to_directory(this_directory)
        if restart:
            print('update finished, restarting')
            AppRunning.exit(42)
        print('update finished')

    @staticmethod
    def update_master(restart=True):
        print('starting update to the master branch')
        this_directory = os.path.abspath(os.path.join(os.path.abspath(__file__), os.path.pardir))
        Updater._updater.extract_master(this_directory)
        if restart:
            print('update finished, restarting')
            AppRunning.exit(42)
        print('update finished')


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
        server_data = requests.post(url).json()
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

    class ThreadDisconnectOnProgramEnd(Thread):
        def run(self):
            while AppRunning.is_running():
                AppRunning.sleep_while_running(2)
            print('disconnecting from server')
            socket.disconnect()

    ThreadDisconnectOnProgramEnd().start()

    def connect():
        socket.emit('login', json.dumps({'uid': ONLINE_DATA['device_id'], 'secret': ONLINE_DATA['device_secret']}))

    def login(ok):
        if not ok:
            print('login with server seems expired, please fix this')
            return
        print('login with server ok')

    def get_attacks(data):
        attacks = list_attacks(data['before'], 100)
        socket.emit('attacks', json.dumps({'userSid': data['userSid'], 'attacks': attacks}))

    def get_bans(data):
        bans = list_bans(data['before'], 100)
        socket.emit('bans', json.dumps({'userSid': data['userSid'], 'bans': bans}))

    def get_statistic_info(sid):
        attacks_total = Database.execute('SELECT COUNT(*) FROM attacks')[0]
        bans_total = Database.execute('SELECT COUNT(*) FROM bans')[0]

        last_midnight_time = int(time.mktime(date.today().timetuple()))
        attacks_today = Database.execute('SELECT COUNT(*) FROM attacks WHERE time > ?', (last_midnight_time,))[0]
        bans_today = Database.execute('SELECT COUNT(*) FROM bans WHERE time > ?', (last_midnight_time,))[0]

        socket.emit('statistic_data', json.dumps(
            {'userSid': sid, 'data': {
             'bans': {'total': bans_total, 'today': bans_today},
                'attacks': {'total': attacks_total, 'today': attacks_today}}}
        ))

    def config(data):
        PROFILES_LOCK.acquire()
        with open(os.path.join(PROFILES_DIR, 'online.json'), 'w') as f:
            json.dump(json.loads(data), f, indent=2)
        PROFILES_LOCK.release()
        load_profiles()

    def update():
        Updater.update()

    def update_master():
        Updater.update_master()

    def get_update_information(user_sid):
        socket.emit('update_info', json.dumps({'userSid': user_sid, 'versionCurrent': VERSION_TAG,
                                               'versionLatest': Updater.get_latest_name()}))

    socket.on('connect', connect)
    socket.on('login', login)
    socket.on('getAttacks', get_attacks)
    socket.on('getBans', get_bans)
    socket.on('getStatisticInfo', get_statistic_info)
    socket.on('config', config)
    socket.on('update', update)
    socket.on('update_master', update_master)
    socket.on('get_update_information', get_update_information)
    socket.connect()


def cli():
    del sys.argv[1]
    if 'login' in sys.argv:
        print(login_with_server(sys.argv[sys.argv.index('login') + 1])[1])
        exit()
    if 'uninstall' in sys.argv:
        os.system("sudo service simple-guardian stop; sudo userdel simple-guardian; sudo rm -r "
                  "/usr/share/simple-guardian/;  sudo rm -r /usr/bin/simple-guardian-client; sudo rm "
                  "/etc/systemd/system/simple-guardian.service")
        print('uninstalled')
        exit()
    if 'update' in sys.argv:
        Updater.init()
        if Updater.update_available() or '-f' in sys.argv:
            Updater.update(restart=False)
        'no update needed'
        exit()
    if 'update-master' in sys.argv:
        Updater.init()
        Updater.update_master(restart=False)
        exit()
    if 'unblock' in sys.argv:
        blocked_ip = None
        if os.geteuid() != 0:
            print('this option must be executed as root')
            exit(1)
        try:
            blocked_ip = sys.argv[sys.argv.index('unblock') + 1]
        except IndexError:
            print('ypu have to specify the IP to unblock')
            exit(1)
        Database.init(os.path.join(CONFIG_DIR, 'db.db'))
        if not IPBlocker.unblock(blocked_ip):
            print('"%s" is not blocked' % blocked_ip)
            AppRunning.exit(0)
        print('%s was unblocked' % blocked_ip)
        AppRunning.exit(0)

    if '-V' in sys.argv or 'version' in sys.argv:
        print(VERSION_TAG)
        exit()
    if 'help' in sys.argv:
        print('recognized commands:')
        print('login loginKey     ...........   logins with online server for remote control')
        print('uninstall          ...........   wipes simple guardian from disc')
        print('update             ...........   updates s-g to the latest version from GitHub releases')
        print('update-master      ...........   updates s-g to the latest version from GitHub master branch')
        print('unblock            ...........   must be executed as root, unblocks IP blocked by s-g')
        print('-V/version         ...........   prints version and exits')
        exit()
    print('for help enter simple-guardian-client help')


def main():
    # Load global configs
    with open(os.path.join(CONFIG_DIR, 'config.json'), 'r') as f:
        CONFIG.update(json.load(f))

    try:
        if sys.argv[1] == 'client':
            cli()
            exit()
    except IndexError:
        pass

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

    print('Blocking all previously blocked IPs')
    IPBlocker.block_all_banned()

    Updater.init()
    update_available = Updater.update_available()
    print('You are up to date' if not update_available
          else 'There is another version on the server: %s (you have %s)' % (Updater.get_latest_name(), VERSION_TAG))
    if update_available and CONFIG.get('updater', {}).get('autoupdate', False):
        Updater.update()

    ThreadScanner().start()
    while AppRunning.is_running():
        try:
            AppRunning.sleep_while_running(10)
        except KeyboardInterrupt:
            AppRunning.set_running(False)


if __name__ == '__main__':
    main()
