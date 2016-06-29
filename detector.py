from hashlib import sha256
from detector_cshash import calculate_cs_hash
import pefile, peutils

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
        if file_hash in self._hashes:
            print "[Detector] Blacklist attachment found: %s" % (file_hash,)
            return True
        return False


class CSBlacklist(Detection):
    """
    Code section black list
    """
    error_message = "File contains a blacklisted Code-Section (.text)"

    def __init__(self, hashes):
        """
        :param hashes: List of SHA256 Hashes
        """
        self._hashes = hashes

    def is_malicious(self, file_content):
        cs_hash = calculate_cs_hash(file_content)
        if cs_hash in self._hashes:
            print "[Detector] Blacklisted code sectionfound: %s" % (cs_hash,)
            return True
        return False


class EntropyDetect(Detection):
    """
    Code section black list
    """
    error_message = "File entropy too high - a potential compressed/encrypted sections found."

    def is_malicious(self, file_content):
        try:
            pe = pefile.PE(data=file_content)
        except pefile.PEFormatError:
            return False

        # peutils implements entropy check
        return peutils.is_probably_packed()


class PEiDComparison(Detection):
    """
    Code section black list
    """
    error_message = "File contains a blacklisted Code-Section (.text)"

    def __init__(self, signature_files):
        """
        :param hashes: List of SHA256 Hashes
        """
        self._sig_files = signature_files
        self._signatures = [peutils.SignatureDatabase(path) for path in signature_files]

    def is_malicious(self, file_content):
        try:
            pe = pefile.PE(data=file_content)
        except pefile.PEFormatError:
            return False

        for signature in self._signatures:
            matches = signature.match(pe, ep_only=True)
            if matches is not None:
                print "[Detector] PEiD Signatures matched: %r" % (matches,)
                return True

        return False