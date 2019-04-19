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
from typing import List, Dict, Set

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

# directory with configuration files
CONFIG_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), os.path.pardir, 'data'))

PROFILES_DIR = os.path.join(CONFIG_DIR, 'profiles')  # directory with profiles
CONFIG = {}  # dictionary with loaded config in main()
ONLINE_DATA = {'loggedIn': False}  # type: Dict[str, any] # data about the online server,
PROFILES = {}  # type: {str: dict}
PROFILES_LOCK = Lock()  # lock used when manipulating with profiles in async
VERSION_TAG = "1.11"  # tag of current version


class Database:
    """
    Synchronized worker with the SQLite database
    """
    queue_in = Queue()  # operations to perform
    queue_out = Queue()  # data to return
    db_lock = Lock()

    @staticmethod
    def init(file_path):  # type: (str) -> None
        """
        Initialize the static database
        :param file_path: path to the saved file with database
        :return: None
        """
        class ThreadDatabase(Thread):
            """
            This thread runs in background and performs all operations with the database if needed
            Creates new database if not exists yet
            """
            def run(self):
                connection = sqlite3.connect(file_path)

                # create the database schema if not exists yet
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
                        data = Database.queue_in.get()  # type: dict
                        # the present key determines what time of data this is
                        if 'sql' in data:  # perform SQL query
                            db_respond = list(connection.execute(data['sql'], data['param']))
                        elif 'commit' in data:  # commit the saved data
                            connection.commit()
                            db_respond = True
                        else:  # not sure what to do, just respond None
                            db_respond = None
                        # return responded object
                        Database.queue_out.put(db_respond)
                    AppRunning.sleep_while_running(0.1)

        # start the background thread with database connection
        ThreadDatabase().start()

    @staticmethod
    def execute(command, data=()):  # type: (str, tuple) -> list
        """
        Executes the command on database
        :param command: SQL command to be executed
        :param data: tuple of data that are safely entered into the SQL command to prevent SQL injection
        :return: list of returned rows
        """
        Database.db_lock.acquire()
        Database.queue_in.put({'sql': command, 'param': data})
        respond = Database.queue_out.get()  # type: list
        Database.db_lock.release()
        return respond

    @staticmethod
    def json(command, table, data=()):  # type: (str, str, tuple) -> list
        """
        Performs SQL query on table and returns the result as list of dictionaries
        :param command: SQL command to be executed
        :param table: target table of the command. From this table the names of columns are parsed
        :param data: tuple of data that are safely entered into the SQL command to prevent SQL injection
        :return: list of rows, rows are dictionaries where keys are names of columns
        """
        columns = [column_data[1] for column_data in Database.execute("PRAGMA table_info(%s)" % table)]
        records = Database.execute(command, data)
        return [{columns[i]: value for i, value in enumerate(record)} for record in records]

    @staticmethod
    def commit():
        """
        Commits the databse to the disc
        :return: None
        """
        Database.db_lock.acquire()
        Database.queue_in.put({'commit': True})
        respond = Database.queue_out.get()
        Database.db_lock.release()
        return respond


class AppRunning:
    """
    This class signalizes or sets if this program's threads should run or should be terminated
    """
    app_running = [True]

    @staticmethod
    def is_running():  # type: () -> bool
        """
        Tests if the program should be running
        :return: True if the program should be running, False if it should terminate itself
        """
        return len(AppRunning.app_running) > 0

    @staticmethod
    def set_running(val):  # type: (bool) -> None
        """
        Sets if the program should be running
        :param val: True if the program should be running, False if it should terminate itself
        :return: None
        """
        if val:
            AppRunning.app_running.append(True)
        else:
            AppRunning.app_running.clear()

    @staticmethod
    def exit(exit_code):  # type: (int) -> None
        """
        Signalizes all threads to exit and then exists with specified exit code
        :param exit_code:
        :return: NOne
        """
        AppRunning.set_running(False)
        exit(exit_code)

    @staticmethod
    def sleep_while_running(seconds):  # type: (float) -> None
        """
        Performs a sleep operation on calling thread. Sleep is interrupted if the program is supposed to terminate
        :param seconds: how long should the thread sleep
        :return: None
        """
        while AppRunning.is_running() and seconds > 0:
            sleep = min(1.0, seconds)
            time.sleep(sleep)
            seconds -= sleep


class IPBlocker:
    """
    Blocks/unblocks IPs
    """
    block_command_path = './blocker'  # path to the executable that blocks the IPs

    @staticmethod
    def list_blocked_ips():  # type: () -> Set[str]
        """
        Lists the blocked IPs from database
        :return: set of the blocked IPs
        """
        return {record[0] for record in Database.execute('SELECT ip FROM bans')}

    @staticmethod
    def ip_is_blocked(ip):  # type: (str) -> bool
        """
        Tests if the IP is blocked
        :param ip: the IP to test
        :return: True if the IP is stated as blocked in the database, False otherwise
        """
        return Database.execute('SELECT COUNT(*) FROM bans WHERE ip = ?', (ip,))[0][0] != 0

    @classmethod
    def block_all_banned(cls):
        """
        Blocks all IPs marked as banned in database
        Useful during the startup of this program
        :return: None
        """
        [cls.block(ip, commit_db=False, use_db=False) for ip in cls.list_blocked_ips()]

    @classmethod
    def block(cls, ip, commit_db=True, use_db=True):  # type: (str, bool, bool) -> bool
        """
        States the IP as blocked in database if enabled and blocks access to this server
        :param ip: IP to block
        :param commit_db: if set to True, the database will be saved to disc after query
        :param use_db:  if set to True, the IP will be marked as blocked id database
        :return: True if blocking was successful, False if already blocked
        """
        if use_db and cls.ip_is_blocked(ip):
            return False
        subprocess.run([cls.block_command_path, 'block', ip])
        if use_db:
            Database.execute('INSERT INTO `bans`(`time`,`ip`) VALUES (?,?);', (time.time(), ip))
            if commit_db:
                Database.commit()
        return True

    @classmethod
    def unblock(cls, ip, commit_db=True):  # type: (str, bool) -> bool
        """
        Unblocks already blocked IP
        :param ip: blocked IP to unblock
        :param commit_db: if set to True, the database will be saved to disc after query
        :return: True if unblock was successful, False if the IP is not blocked
        """
        if not cls.ip_is_blocked(ip):
            return False
        subprocess.run([cls.block_command_path, 'unblock', ip])
        Database.execute('DELETE FROM bans WHERE ip = ?', (ip,))
        if commit_db:
            Database.commit()
        return True


class ThreadScanner(Thread):
    """
    This thread performs the scanning of the logs, looking for attacks and blocking
    """
    def run(self):
        while AppRunning.is_running():
            print('scanning for attacks')
            time_scan_start = time.time()
            commit_db = False

            PROFILES_LOCK.acquire()
            profiles_copy = dict(PROFILES)
            PROFILES_LOCK.release()

            for profile, profile_data in profiles_copy.items():
                if 'parser' not in profile_data:  # link the parser with the profile
                    profile_data['parser'] = log_manipulator.LogParser(profile_data['logFile'], profile_data['filters'])
                    PROFILES_LOCK.acquire()
                    if profile in PROFILES:  # propagate the change into upcoming scans
                        PROFILES[profile]['parser'] = profile_data['parser']
                    PROFILES_LOCK.release()

                try:
                    attacks = profile_data['parser'].parse_attacks(max_age=profile_data['scanRange'] * 2)
                except FileNotFoundError:
                    continue

                # times of parsed attacks. Every time is unique identification key, if two attacks were made at the same
                # timestamp, then a millisecond is added to one of them to ensure the uniqueness
                known_attack_timestamps = []  # type: List[int]

                for ip, ip_attacks in attacks.items():  # IP and list of IP's attacks
                    for i, attack_data in enumerate(ip_attacks):
                        # TIMESTAMP must be unique
                        while attack_data['TIMESTAMP'] in known_attack_timestamps:
                            attack_data['TIMESTAMP'] += 1
                        known_attack_timestamps.append(attack_data['TIMESTAMP'])
                        attacks[ip][i].update(attack_data)

                        # Check if this attack already exists in our database and if not add it and set the db to
                        # save to disc after everything is added
                        if Database.execute('SELECT COUNT(*) FROM attacks WHERE ip = ? AND time = ? AND profile = ?',
                                            (ip, attack_data['TIMESTAMP'], profile))[0][0] == 0:
                            Database.execute('INSERT INTO `attacks`(`time`,`ip`,`data`,`profile`,`user`) '
                                             'VALUES (?,?,?,?,?);',
                                             (attack_data['TIMESTAMP'], ip, json.dumps(attack_data), profile,
                                              attack_data['USER'] if 'USER' in attack_data else None))
                            commit_db = True

                # get the offenders who shall be blocked
                offenders = profile_data['parser'].get_habitual_offenders(profile_data['maxAttempts'],
                                                                          profile_data['scanRange'],
                                                                          attacks=attacks)
                for offender_ip in offenders.keys():  # block their IPs
                    if IPBlocker.block(offender_ip, commit_db=False):
                        # do not commit the DB now, commit only after everyone is blocked
                        commit_db = True
            if commit_db:
                Database.commit()
            print('scanning for attacks completed, took %.1f seconds' % (time.time() - time_scan_start))
            AppRunning.sleep_while_running(CONFIG['scanTime'])


class Updater:
    """
    Updater of this Simple Guardian client
    """
    _updater = None  # type: github_updater.GithubUpdater

    @staticmethod
    def init():
        """
        Initialize the Updater with data from config
        :return: None
        """
        Updater._updater = github_updater.GithubUpdater(CONFIG['updater']['githubOwner'],
                                                        CONFIG['updater']['githubRepo'])

    @staticmethod
    def update_available():  # type: () -> bool
        """
        Check the most recent version tag from the server and compare it to the VERSION_TAG variable
        :return: True if local and remote version tags differ, False if they are the same
        """
        return VERSION_TAG != Updater._updater.get_latest_release_tag()

    @staticmethod
    def get_latest_name():  # type: () -> str
        """
        Gets the name of the latest release tag
        :return: the name of the latest release tag
        """
        return Updater._updater.get_latest_release_tag()

    @staticmethod
    def update(restart=True):  # type: (bool) -> None
        """
        Updates to the latest release from GitHub repository
        :param restart: if set to True, this program will automatically restart to new version after copying new files
        :return: None
        """
        print('starting update')
        this_directory = os.path.abspath(os.path.join(os.path.abspath(__file__), os.path.pardir))
        Updater._updater.get_and_extract_newest_release_to_directory(this_directory, ['blocker'])
        if restart:
            print('update finished, restarting')
            AppRunning.exit(42)
        print('update finished')

    @staticmethod
    def update_master(restart=True):  # type: (bool) -> None
        """
        Updates to the master branch from GitHub repository
        :param restart: if set to True, this program will automatically restart to new version after copying new files
        :return: None
        """
        print('starting update to the master branch')
        this_directory = os.path.abspath(os.path.join(os.path.abspath(__file__), os.path.pardir))
        Updater._updater.extract_master(this_directory, ['blocker'])
        if restart:
            print('update finished, restarting')
            AppRunning.exit(42)
        print('update finished')


def list_attacks(before=None, max_limit=None):  # type: (int, int) -> List[dict]
    """
    Lists attacks from database and returns them as the list of the rows
    Rows are dictionaries where keys are column names
    :param before: maximum id of the attack, if None then no limit is set
    :param max_limit: maximum number of returned results, if set to None then all results are returned
    :return: list of the rows of attacks from the database, rows are dictionaries where keys are column names
    """
    sql = 'SELECT * FROM attacks'
    if before is not None:
        sql += ' WHERE id < ?'
    sql += ' ORDER BY id DESC'
    if max_limit is not None:
        sql += ' LIMIT ' + str(max_limit)
    return Database.json(sql, 'attacks', (before,) if before is not None else ())


def list_bans(before=None, max_limit=None):  # type: (int, int) -> List[dict]
    """
    Lists bans from database and returns them as the list of the rows
    Rows are dictionaries where keys are column names
    :param before: maximum id of the attack, if None then no limit is set
    :param max_limit: maximum number of returned results, if set to None then all results are returned
    :return: list of the rows of bans from the database, rows are dictionaries where keys are column names
    """
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


def load_profiles():  # type: () -> None
    """
    Loads profiles from disc
    :return: None
    """
    print('Loading profiles')
    PROFILES_LOCK.acquire()
    PROFILES.clear()
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


def pair_with_server(url):  # type: (str) -> (bool, str)
    """
    Pairs this device with an account on the Simple Guardian server
    :param url: URL generated by creating a new device on Simple Guardian Server web
    :return: tuple (bool, str): True if logged in successfully, False if not, explaining message string:
    """
    try:
        server_data = requests.post(url).json()
    except requests.exceptions.ConnectionError:
        return False, 'cannot login, server is unreachable'
    except json.JSONDecodeError:
        return False, 'server returned unusable answer'
    ONLINE_DATA.update(server_data)
    ONLINE_DATA['loggedIn'] = True
    # noinspection PyTypeChecker
    ONLINE_DATA['server_url'] = url.split("/api/", 1)[0]
    with open(os.path.join(CONFIG_DIR, 'server.json'), 'w') as f:
        json.dump(ONLINE_DATA, f, indent=1)
    return True, 'Logged in'


def init_online():  # type: () -> None
    """
    This function initializes the online part communicating with SG server. Must be already paired with account on
    the server in order to initialize online part
    :return: None
    """
    socket = HSocket(ONLINE_DATA['server_url'], auto_connect=False)

    class ThreadDisconnectOnProgramEnd(Thread):
        """
        This thread forces disconnection of the socket when the client is supposed to end
        """
        def run(self):
            while AppRunning.is_running():
                AppRunning.sleep_while_running(2)
            print('disconnecting from server')
            socket.disconnect()

    ThreadDisconnectOnProgramEnd().start()  # run the thread that will close the socket on program's exit

    def connect():  # type: () -> None
        """
        Fired on successful connection to the server.
        Send authorisation request to the server.
        :return: None
        """
        socket.emit('login', json.dumps({'uid': ONLINE_DATA['device_id'], 'secret': ONLINE_DATA['device_secret']}))

    def login(ok):  # type: (bool) -> None
        """
        Fired when server responds on our authorisation request
        Prints the result of the login to the console
        :param ok: True if our login is successful, False if there was something wrong with our request
        :return: None
        """
        if not ok:
            print('login with server seems expired, please fix this')
            return
        print('login with server ok')

    def get_attacks(data):  # type: (dict) -> None
        """
        Fired when the remote user asks us about saved attacks from SG Server's web interface
        Responds him with results from our database
        :param data: dictionary. Keys are 'before' - max id of the attack in database and
        'userSid' - id of the user on the SG's web interface
        :return: None
        """
        attacks = list_attacks(data['before'], 100)
        socket.emit('attacks', json.dumps({'userSid': data['userSid'], 'attacks': attacks}))

    def get_bans(data):  # type: (dict) -> None
        """
        Fired when the remote user asks us about saved bans from SG Server's web interface
        Responds him with results from our database
        :param data: dictionary. Keys are 'before' - max id of the bans in database and
        'userSid' - socket's id of the user on the SG's web interface
        :return: None
        """
        bans = list_bans(data['before'], 100)
        socket.emit('bans', json.dumps({'userSid': data['userSid'], 'bans': bans}))

    def get_statistic_info(sid):  # type: (str) -> None
        """
        User on the SG server's web interface wants to know how many attacks and bans were today and total
        Send him those data
        :param sid: socket's id of the user on the SG's web interface
        :return: None
        """
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

    def config(data):  # type: (dict) -> None
        """
        Server sends us new dictionary with profiles. Save it and apply the new profiles
        :param data: dictionary with profiles
        :return:  None
        """
        PROFILES_LOCK.acquire()
        with open(os.path.join(PROFILES_DIR, 'online.json'), 'w') as f:
            json.dump(json.loads(data), f, indent=2)
        PROFILES_LOCK.release()
        load_profiles()

    def update():  # type: () -> None
        """
        Server asks us to update to the newest release from GitHub repo
        :return: None
        """
        Updater.update()

    def update_master():  # type: () -> None
        """
        Server asks us to update to the master branch from GitHub repo
        :return: None
        """
        Updater.update_master()

    def unblock_ip(ip):  # type: (str) -> None
        """
        Server asks us to unblock blocked IP. Ok.
        :param ip: IP address to unblock
        :return: None
        """
        IPBlocker.unblock(ip)

    def get_update_information(user_sid):  # type: (str) -> None
        """
        User on the SG server's web interface wants to know our version and the newest version available
        :param user_sid: socket's id of the user on the SG's web interface
        :return: None
        """
        socket.emit('update_info', json.dumps({'userSid': user_sid, 'versionCurrent': VERSION_TAG,
                                               'versionLatest': Updater.get_latest_name()}))

    # initialize all handlers and then connect
    socket.on('connect', connect)
    socket.on('login', login)
    socket.on('getAttacks', get_attacks)
    socket.on('getBans', get_bans)
    socket.on('getStatisticInfo', get_statistic_info)
    socket.on('config', config)
    socket.on('update', update)
    socket.on('update_master', update_master)
    socket.on('get_update_information', get_update_information)
    socket.on('unblock_ip', unblock_ip)
    socket.connect()


def cli():
    """
    Run CLI
    :return: None
    """
    del sys.argv[1]

    if 'uninstall' in sys.argv:
        os.system("sudo service simple-guardian stop; sudo userdel simpleguardian; sudo rm -r "
                  "/usr/share/simple-guardian/;  sudo rm -r /usr/bin/simple-guardian-client; sudo rm "
                  "/etc/systemd/system/simple-guardian.service")
        print('uninstalled')
        exit()
    if '-V' in sys.argv or 'version' in sys.argv:
        print(VERSION_TAG)
        exit()
    if 'help' in sys.argv:
        print('recognized commands:')
        print('login loginKey     ...........   logins with online server for remote control')
        print('uninstall          ...........   wipes simple guardian from disc')
        print('update             ...........   updates s-g to the latest version from GitHub releases')
        print('update-master      ...........   updates s-g to the latest version from GitHub master branch')
        print('unblock            ...........   unblocks IP blocked by s-g')
        print('-V/version         ...........   prints version and exits')
        exit()

    # commands below require root privileges
    if os.geteuid() != 0:
        print('this option must be executed as root')
        exit(1)

    if 'login' in sys.argv:
        print(pair_with_server(sys.argv[sys.argv.index('login') + 1])[1])
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

    # Initialize database
    Database.init(os.path.join(CONFIG_DIR, 'db.db'))

    print('Blocking all IPs saved in database')
    IPBlocker.block_all_banned()

    # Check for updates and perform automatic update if enabled and available
    Updater.init()
    update_available = Updater.update_available()
    print('You are up to date' if not update_available
          else 'There is another version on the server: %s (you have %s)' % (Updater.get_latest_name(), VERSION_TAG))
    if update_available and CONFIG.get('updater', {}).get('autoupdate', False):
        Updater.update()

    # Start scanning of the logs
    ThreadScanner().start()

    # Terminate the program when CTRL+C is pressed
    while AppRunning.is_running():
        try:
            AppRunning.sleep_while_running(10)
        except KeyboardInterrupt:
            AppRunning.set_running(False)


if __name__ == '__main__':
    main()
