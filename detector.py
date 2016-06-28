from hashlib import sha256


class Detection(object):
    def __init__(self):
        pass

    def is_malicious(self, file_content):
        raise NotImplementedError()


class Blacklist(Detection):
    def __init__(self, hashes):
        """
        :param hashes: List of SHA256 Hashes
        """
        self._hashes = hashes

    def is_malicious(self, file_content):
        file_hash = sha256(file_content).hexdigest()
        if file_hash in self._hashes:
            return True
        return False

