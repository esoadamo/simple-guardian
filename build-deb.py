#!/usr/bin/env python3
import os
import re
import shutil
from hashlib import md5
from os import path
from subprocess import call

print('build starting')

BUILD_DIR = 'builds/deb-build-curr'
BUILD_OUTPUT_DIR = 'builds/out'

WANTED_FILES = [
    'blocker',
    'github_updater.py',
    'requirements.txt',
    'http_socket_client.py',
    'log_manipulator.py',
    'simple-guardian.py',
    'data/profiles/default.json',
    'data/config.json'
]

BUILD_DIR = path.abspath(BUILD_DIR)
BUILD_OUTPUT_DIR = path.abspath(BUILD_OUTPUT_DIR)

if not path.isdir(BUILD_OUTPUT_DIR):
    os.makedirs(BUILD_OUTPUT_DIR)

# remove previous builds
if path.isdir(BUILD_DIR):
    print('previous build found, removing...')
    shutil.rmtree(BUILD_DIR)

# create required directories
print('creating directory structure')
os.makedirs(BUILD_DIR)
os.makedirs(path.join(BUILD_DIR, 'DEBIAN'))
os.makedirs(path.join(BUILD_DIR, 'usr', 'share', 'simple-guardian'))
os.makedirs(path.join(BUILD_DIR, 'usr', 'bin'))
os.makedirs(path.join(BUILD_DIR, 'etc', 'systemd', 'system'))

# parse the version
print('parsing last version')
with open('simple-guardian.py', 'r') as f:
    version = re.search('VERSION_TAG\\s*=\\s["\'](.*)[\'"]', f.read()).groups()[0]

# create file DEBIAN/conffiles
print('writing DEBIN config files')
with open(path.join(BUILD_DIR, 'DEBIAN', 'conffiles'), 'w') as f:
    f.write("""/usr/share/simple-guardian/data/config.json
""")

# make post install script
print('creating post install script')
with open(path.join(BUILD_DIR, 'DEBIAN', 'postinst'), 'w') as f:
    f.write("""#!/bin/bash
useradd simpleguardian
usermod -a -G adm simpleguardian
chown -R simpleguardian:simpleguardian /usr/share/simple-guardian
chown root:root /usr/share/simple-guardian/blocker
chmod +x /usr/share/simple-guardian/blocker
chmod u+s /usr/share/simple-guardian/blocker
python3 -m venv /usr/share/simple-guardian/venv
/usr/share/simple-guardian/venv/bin/pip install --no-cache-dir -r /usr/share/simple-guardian/requirements.txt
rm /usr/share/simple-guardian/requirements.txt
chmod +x /usr/bin/simple-guardian-client
chown root:root /usr/bin/simple-guardian-client
service simple-guardian restart
systemctl daemon-reload
""")
os.chmod(path.join(BUILD_DIR, 'DEBIAN', 'postinst'), 0o775)

# make prerm script
print('creating post install script')
with open(path.join(BUILD_DIR, 'DEBIAN', 'prerm'), 'w') as f:
    f.write("""#!/bin/bash
rm /usr/bin/simple-guardian-client
rm -r /usr/share/simple-guardian/venv
rm /etc/systemd/system/simple-guardian.service
userdel simpleguardian
""")
os.chmod(path.join(BUILD_DIR, 'DEBIAN', 'prerm'), 0o775)

# write service data
print('writing service')
with open(path.join(BUILD_DIR, 'etc', 'systemd', 'system', 'simple-guardian.service'), 'w') as f:
    f.write("""[Unit]
Description=Simple-guardian service
After=network.target

[Service]
Type=simple
User=simpleguardian
WorkingDirectory=/usr/share/simple-guardian
ExecStart=/usr/share/simple-guardian/venv/bin/python simple-guardian.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")

# copy all wanted files
print('copying all wanted files')
for file in WANTED_FILES:
    file_from = path.abspath(file)
    file_to = path.join(BUILD_DIR, 'usr', 'share', 'simple-guardian')
    for part in file.split('/'):
        file_to = path.join(file_to, part)
    file_to_dir = path.abspath(path.join(file_to, path.pardir))
    if not path.exists(file_to_dir):
        os.makedirs(file_to_dir)
    shutil.copy(file_from, file_to)

# add client
print('adding simple guardian client')
with open(path.join(BUILD_DIR, 'usr', 'bin', 'simple-guardian-client'), 'w') as f:
    f.write("""#!/bin/bash
cd /usr/share/simple-guardian
./venv/bin/python simple-guardian.py client "$@"
""")

# create md5 hashes and count size
print('listing files for hashing and size counting')
files_extracted = [os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.expanduser(BUILD_DIR))
                   for f in fn if not dp.startswith(path.join(BUILD_DIR, 'DEBIAN'))]

total_size = 0
hashes = {}
for f in files_extracted:
    total_size += path.getsize(f)
    with open(f, 'rb') as ff:
        hashes[f] = md5(ff.read()).hexdigest()

print('creating file with hashes')
with open(path.join(BUILD_DIR, 'DEBIAN', 'md5sum'), 'w') as f:
    for file_path, file_hash in hashes.items():
        f.write('%s %s\n' % (path.basename(file_path), file_hash))

# create file DEBIAN/control
print('writing DEBIAN control')
with open(path.join(BUILD_DIR, 'DEBIAN', 'control'), 'w') as f:
    f.write("""Package: simple-guardian
Version: %s
Architecture: all
Essential: no
Section: security
Priority: optional
Depends: python3, systemd, python3-pip, python3-venv
Maintainer: Adam Hlaváček
Installed-Size: %d
Description: Protection against brute force attacks
License: MIT
""" % (version, total_size // 1024))

output_file = path.join(BUILD_OUTPUT_DIR, 'simpleguardian.%s.deb' % version)
if call(['dpkg', '-b', BUILD_DIR, output_file]) == 0:
    print('build ok, removing build source')
    print('your build is at %s' % output_file)
    shutil.rmtree(BUILD_DIR)
