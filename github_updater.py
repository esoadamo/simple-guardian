import os
import shutil
import tempfile
import zipfile
from typing import List

import requests


class GithubUpdater:
    """
    Interface for obtaining latest source codes from GitHub repository
    """

    def __init__(self, repo_owner, repo_name):  # type: (str, str) -> None
        """
        Initializes the GitHub updater
        :param repo_owner: owner of the GitHub repository to update from
        :param repo_name: name of the GithHub repository to update from
        """
        self.url_release = "https://api.github.com/repos/%s/%s/releases/latest" % (repo_owner, repo_name)
        self.url_master_zip = "https://github.com/%s/%s/archive/master.zip" % (repo_owner, repo_name)

    def get_latest_release_data(self):  # type: () -> dict
        """
        Uses GitHub API to obtain all data about latest release and return them as a dict
        :return: all data about latest release and as a dict
        """
        return requests.get(self.url_release).json()

    def get_latest_release_tag(self):  # type: () -> str
        """
        Fetches the tag of the latest release
        :return: the tag of the latest release from GitHub repository
        """
        return self.get_latest_release_data()['tag_name']

    def get_latest_release_zip(self, target_file):  # type: (str) -> None
        """
        Downloads the zip with a source code of the latest release from GitHub
        :param target_file: where to download the zip file to
        :return: None
        """
        r = requests.get(self.get_latest_release_data()['zipball_url'], stream=True)
        with open(target_file, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

    def get_master(self, target_file):  # type: (str) -> None
        """
        Downloads the current master branch as a zip file
        :param target_file: where to download the master branch zip file to
        :return: None
        """
        r = requests.get(self.url_master_zip, stream=True)
        with open(target_file, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

    def get_and_extract_newest_release_to_directory(self, target_directory, skip_file_names=None):
        # type: (str, List[str] or None) -> None
        """
        Downloads and extracts newest release to specified directory
        :param target_directory: here will be the code of the newest release placed
        :param skip_file_names: files with names inside this list will not be extracted
        :return: None
        """
        zip_file = tempfile.mkstemp()[1]
        self.get_latest_release_zip(zip_file)
        self._extract_zip(zip_file, target_directory, skip_file_names)

    def extract_master(self, target_directory, skip_file_names=None):  # type: (str, List[str] or None) -> None
        """
        Downloads and extracts code from master branch to specified directory
        :param target_directory: here will be the code from master branch placed
        :param skip_file_names: files with names inside this list will not be extracted
        :return: None
        """
        zip_file = tempfile.mkstemp()[1]
        self.get_master(zip_file)
        self._extract_zip(zip_file, target_directory, skip_file_names)

    @staticmethod
    def _extract_zip(zip_path, target_directory, skip_file_names=None):  # type: (str, str, List[str] or None) -> None
        """
        Extract zip with source code to target directory and deletes the zip file
        :param zip_path: zip file to be extracted
        :param target_directory: where to place the source code from the zip file
        :param skip_file_names: files with names inside this list will not be extracted
        :return: None
        """
        skip_file_names = skip_file_names if skip_file_names is not None else []
        extracted_dir = tempfile.mkdtemp()
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extracted_dir)
        os.unlink(zip_path)
        source_dir = os.path.join(extracted_dir, os.listdir(extracted_dir)[0])
        files_from_to = {}

        def process_dir(directory, dir_prefix=""):
            for filename in os.listdir(directory):
                file_path = os.path.abspath(os.path.join(source_dir, dir_prefix, filename))
                if os.path.isfile(file_path):
                    if filename in skip_file_names:
                        continue
                    files_from_to[file_path] = os.path.abspath(os.path.join(target_directory, dir_prefix, filename))
                elif os.path.isdir(file_path):
                    process_dir(file_path, os.path.join(dir_prefix, filename))

        process_dir(source_dir)

        for file_from, file_to in files_from_to.items():
            parent_dir = os.path.abspath(os.path.join(file_to, os.path.pardir))
            if not os.path.isdir(parent_dir):
                os.makedirs(parent_dir)
                pass
            shutil.move(file_from, file_to)
        shutil.rmtree(extracted_dir)
