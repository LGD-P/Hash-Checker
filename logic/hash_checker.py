import os
import hashlib
from pathlib import Path

from .const import HASHES_AVAILABLE



class HashChecker:

    @staticmethod
    def hash_string(hash_name: str, string: str) -> str:
        hash_obj = hashlib.new(hash_name)
        hash_obj.update(string.encode('utf-8'))
        return hash_obj.hexdigest()

    @staticmethod
    def hash_file(hash_name: str, file: Path) -> str:
        hash_obj = hashlib.new(hash_name)
        with open(file, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hash_obj.update(chunk)
        return hash_obj.hexdigest()

    @staticmethod
    def generate_hashes_form_string(string: str, hashes_available: list = HASHES_AVAILABLE) -> str:
        result = {}
        for k, v in enumerate(hashes_available):
            value = HashChecker.hash_string(v, string)
            result[v] = value
        return result

    @staticmethod
    def generate_hashes_from_file(file: Path, hashes_available: list = HASHES_AVAILABLE) :
        if not file.exists() or file.is_dir() or not os.access(file, os.R_OK):
            return False

        hashes_possible = {}
        for hash_name in hashes_available:
            file_hash = HashChecker.hash_file(hash_name, file)
            hashes_possible[hash_name] = file_hash
        return hashes_possible

    @staticmethod
    def compare_hash_to_string(hash_to_compare: str, string: str) -> list:
        hashes_possible = HashChecker.generate_hashes_form_string(string)
        for k, v in hashes_possible.items():
            string_hash = HashChecker.hash_string(k, string)
            if hash_to_compare == string_hash:
                result = [string, k, hash_to_compare]
                return result

        result = [string]
        return result

    @staticmethod
    def compare_hash_to_file(hash_to_compare: str, file_path: Path) :
        hashes_possible = HashChecker.generate_hashes_from_file(file_path)
        if hashes_possible is False:
            return False
        for hash_name, file_hash in hashes_possible.items():
            if file_hash == hash_to_compare:
                result = [file_path, hash_name, hash_to_compare]
                return result
        result = [file_path]
        return result
