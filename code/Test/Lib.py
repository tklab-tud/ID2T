import hashlib

from definitions import ROOT_DIR

# TODO: generate better test pcap (1000-2000 packets)
test_pcap = ROOT_DIR + "/../resources/test/test.pcap"


def get_sha256(file):
    sha = hashlib.sha256()
    with open(file, 'rb') as f:
        while True:
            data = f.read(0x100000)
            if not data:
                break
            sha.update(data)
    return sha.hexdigest()
