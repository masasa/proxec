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
    Detect packed sections based on entropy
    """
    error_message = "File entropy too high - a potential compressed/encrypted sections found."

    def is_malicious(self, file_content):
        try:
            pe = pefile.PE(data=file_content)
        except pefile.PEFormatError:
            return False

        # peutils implements entropy check
        return peutils.is_probably_packed(pe)


class PEiDComparison(Detection):
    """
    Code section black list
    """
    error_message = "File is PEiD blacklisted"

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


class APIDetection(Detection):
    """
    Detect APIs in a PEfile
    """
    error_message = "File contains a malicious APIs"

    def __init__(self, malicious_api, threshold):
        """

        :param malicious_api: List of API functions
        :param threshold: How many APIs shuold appear from list in order to return true
        """
        self._mal_api = set(malicious_api)
        self._threshold = threshold

    def is_malicious(self, file_content):
        try:
            pe = pefile.PE(data=file_content)
        except pefile.PEFormatError:
            return False

        import_functions = []

        pe.parse_data_directories()

        # Collect import functions
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print entry.dll
            for imp in entry.imports:
                import_functions.append(imp.name)

        # Match known APIs
        if len(set(import_functions).intersection(self._mal_api)) > self._threshold:
            print '[Detector] API Detector blocked attachment: %r' % (set(import_functions).intersection(self._mal_api),)
            return True

        return False