import os
import shutil
import tempfile
import zipfile

import requests


class GithubUpdater:
    def __init__(self, repo_owner, repo_name):
        self.url_release = "https://api.github.com/repos/%s/%s/releases/latest" % (repo_owner, repo_name)
        self.url_master_zip = "https://github.com/%s/%s/archive/master.zip" % (repo_owner, repo_name)

    def get_latest_release_data(self):
        return requests.get(self.url_release).json()

    def get_latest_release_tag(self):
        return self.get_latest_release_data()['tag_name']

    def get_latest_release_zip(self, target_file):
        r = requests.get(self.get_latest_release_data()['zipball_url'], stream=True)
        with open(target_file, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

    def get_master(self, target_file):
        r = requests.get(self.url_master_zip, stream=True)
        with open(target_file, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

    def get_and_extract_newest_release_to_directory(self, target_directory):
        zip_file = tempfile.mkstemp()[1]
        self.get_latest_release_zip(zip_file)
        self._extract_zip(zip_file, target_directory)

    def extract_master(self, target_directory):
        zip_file = tempfile.mkstemp()[1]
        self.get_master(zip_file)
        self._extract_zip(zip_file, target_directory)

    @staticmethod
    def _extract_zip(zip_path, target_directory):
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
