import pefile
import sys
from hashlib import sha256


def calculate_cs_hash(data):
    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError:
        return None

    for section in pe.sections:
        if not section.Name.startswith(".text"):
            continue

        hex_digest = sha256(section.get_data()).hexdigest()
        print ">> Section %r size: %d hash: %s" % (section.Name, len(section.get_data()), hex_digest)

        return hex_digest

if __name__ == '__main__':
    calculate_cs_hash(open(sys.argv[1], "rb").read())