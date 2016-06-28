from hashlib import sha256


class Detection(object):
    error_message = ""

    def __init__(self):
        pass

    def is_malicious(self, file_content):
        raise NotImplementedError()


class Blacklist(Detection):
    error_message = "File was blacklisted"

    def __init__(self, hashes):
        """
        :param hashes: List of SHA256 Hashes
        """
        self._hashes = hashes

    def is_malicious(self, file_content):
        file_hash = sha256(file_content).hexdigest()
        print "$$ (%d) %r" % (len(file_content), file_content)
        if file_hash in self._hashes:
            return True
        return False

