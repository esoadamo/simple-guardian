#!/usr/bin/env python3
import os
import shutil
import sys
from subprocess import check_call, CalledProcessError, Popen

target_directory = "/usr/share/simple-guardian"
username = "simpleguardian"


def run(cmd, accept_return_codes=None):  # type: (list, list) -> int
    if accept_return_codes is None:
        accept_return_codes = []
    accept_return_codes.append(0)
    try:
        p = Popen(cmd)
        p.wait()
        if p.returncode not in accept_return_codes:
            print('ERRROR: running command "%s" failed for some reason' % cmd)
            exit(1)
        return p.returncode
    except OSError:
        print('ERRROR: running command "%s" failed - the command was not found' % cmd)
        exit(1)


# CHECK REQUIREMENTS
# - check Python 3 is ued
if sys.version_info[0] != 3:
    print('you must run this auto installer with Python 3')
    print("ERROR: CHECKING REQUIREMENTS FAILED")
    exit(1)
# - check root right are available
if os.geteuid() != 0:
    print('you must give this script root\'s rights')
    print("ERROR: CHECKING REQUIREMENTS FAILED")
    exit(1)
# - check that pip and venv are installed:
try:
    check_call([sys.executable, '-m', 'pip', '-V'])
    check_call([sys.executable, '-m', 'venv', '-h'])
except CalledProcessError:
    print('it seems that pip/venv is/are missing. I will try to compensate that')
    try:
        check_call(['apt', 'install', '-y', 'python3-pip', 'python3-venv'])
    except CalledProcessError:
        print("that didn't make it better, this one is on you")
        print("try to install python3-pip python3-venv on Ubuntu/Debian based systems")
        print("ERROR: CHECKING REQUIREMENTS FAILED")
        exit(1)

print('copying files into %s' % target_directory)
sg_dir = os.path.dirname(os.path.realpath(__file__))
excluded_dirs = ['__pycache__', 'venv', 'wenv', 'builds']
files_from_to = {}


def process_dir(directory, dir_prefix=""):
    for filename in os.listdir(directory):
        file_path = os.path.abspath(os.path.join(sg_dir, dir_prefix, filename))
        if os.path.isfile(file_path):
            files_from_to[file_path] = os.path.abspath(os.path.join(target_directory, dir_prefix, filename))
        elif os.path.isdir(file_path) and not filename.startswith('.') and filename not in excluded_dirs:
            process_dir(file_path, os.path.join(dir_prefix, filename))


process_dir(sg_dir)
for file_from, file_to in files_from_to.items():
    parent_dir = os.path.abspath(os.path.join(file_to, os.path.pardir))
    if not os.path.isdir(parent_dir):
        os.makedirs(parent_dir)
        pass
    shutil.copy(file_from, file_to)

print('creating %s user' % username)
if run(["useradd", username], [9]) != 9:  # 9 means user already exists
    print('adding %s to adm group' % username)
    run(["usermod", '-a', '-G', 'adm', username])

print('giving folder permissions to %s' % username)
run(["chown", "-R", '{0}:root'.format(username), target_directory])

print('giving executing rights on blocker executable and assigning him to the root with setuid')
run(["chown", "root:root", "%s/blocker" % target_directory])
run(["chmod", "+x", "%s/blocker" % target_directory])
run(["chmod", "u+s", "%s/blocker" % target_directory])

if not os.path.isdir(os.path.join(target_directory, 'venv')):
    print('creating venv')
    run([sys.executable, "-m", "venv", os.path.join(target_directory, 'venv')])

print('installing requirements')
pip_path = os.path.join(target_directory, 'venv', 'bin', 'pip')
run([pip_path, "install", '--no-cache-dir', "-r", os.path.join(target_directory, 'requirements.txt')])

print('adding client simple-guardian-client')
with open('/usr/bin/simple-guardian-client', 'w') as f:
    f.write("""#!/bin/bash
cd "%s"
./venv/bin/python simple-guardian.py client "$@"
""" % target_directory)
run(["chmod", "+x", "/usr/bin/simple-guardian-client"])

print('installing system service')
with open('/etc/systemd/system/simple-guardian.service', 'w') as f:
    f.write("""[Unit]
Description=Simple-guardian service
After=network.target

[Service]
Type=simple
User=%s
WorkingDirectory=%s
ExecStart=%s/venv/bin/python simple-guardian.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
""" % (username, target_directory, target_directory))

print('enabling service auto startup')
run(['systemctl', 'enable', 'simple-guardian'])

print('starting service')
run(['service', 'simple-guardian', 'start'])
print('you are protected now!')
