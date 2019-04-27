import os
from hashlib import md5
from os import path
from subprocess import call
from sys import executable


class RequirementsUpdater:
    """
    Checks requirements file for changes against database and updates if necessary
    """

    def __init__(self, requirements_file='requirements.txt', hashes_file='.requirements.md5'):
        # type: (str, str) -> None
        """
        Initializes RequirementsUpdater with required data
        :param requirements_file='requirements.txt': path to the file with pip requirements
        :param hashes_file='.requirements.md5': path to the file with requirements file's hash
        """
        self.requirements_file = path.abspath(requirements_file)
        self.hashes_file = path.abspath(hashes_file)

    def check(self):  # type: () -> bool
        """
        Checks if requirements file has not changed
        :return: True hash of the current requirements file is same as the saved hash
        """
        if not path.exists(self.hashes_file):
            return False

        with open(self.hashes_file, 'r') as f:
            hash_saved = f.read().strip()

        with open(self.requirements_file, 'rb') as f:
            hash_current = md5(f.read()).hexdigest()

        return hash_current == hash_saved

    def save_hash(self):  # type: () -> None
        """
        Saves hash of current requirements file
        :return: None
        """
        if not path.exists(self.hashes_file):
            par_dir = path.abspath(path.join(self.hashes_file, path.pardir))
            if not os.path.exists(par_dir):
                os.makedirs(par_dir)

        with open(self.requirements_file, 'rb') as r:
            with open(self.hashes_file, 'w') as w:
                w.write(md5(r.read()).hexdigest())

    def update(self):  # type: () -> bool
        """
        Updates current packages from requirements file if necessary
        :return: True if update was not needed or successful, False if update failed
        """
        if self.check():
            return True
        print('new requirements are present, updating...')
        if call([executable, '-m', 'pip', '--no-cache-dir', 'install',
                 '--upgrade', '--user', '-r', self.requirements_file]) != 0:
            print('!!!!! updating requirements failed!!!')
            return False
        print('requirements update complete')
        self.save_hash()
        return True
