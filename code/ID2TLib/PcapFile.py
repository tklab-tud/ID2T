import hashlib
import os.path

import ID2TLib.libpcapreader as pr


class PcapFile(object):
    def __init__(self, pcap_file_path: str):
        """
        Creates a new PcapFile associated to the PCAP file at pcap_file_path.

        :param pcap_file_path: The path to the PCAP file
        """
        self.pcap_file_path = pcap_file_path

    def merge_attack(self, attack_pcap_path: str):
        """
        Merges the loaded PCAP with the PCAP at attack_pcap_path.

        :param attack_pcap_path: The path to the PCAP file to merge with the PCAP at pcap_file_path
        :return: The file path of the resulting PCAP file
        """
        pcap = pr.pcap_processor(self.pcap_file_path, "False")
        file_out_path = pcap.merge_pcaps(attack_pcap_path)
        return file_out_path

    def get_file_hash(self):
        """
        Returns the hash for the loaded PCAP file. The hash is calculated bsaed on:

        - the file size in bytes
        - the first 224*40000 bytes of the file

        :return: The hash for the PCAP file as string.
        """
        # Blocksize in bytes
        const_blocksize = 224
        # Number of blocks to read at beginning of file
        const_max_blocks_read = 40000

        # Initialize required variables
        hasher = hashlib.sha224()
        blocks_read = 0

        # Hash calculation
        with open(self.pcap_file_path, 'rb') as afile:
            # Add filename -> makes trouble when renaming the PCAP
            # hasher.update(afile.name.encode('utf-8'))

            # Add file's last modification date -> makes trouble when copying the PCAP
            # hasher.update(str(time.ctime(os.path.getmtime(self.pcap_file_path))).encode('utf-8'))

            # Add file size
            hasher.update(str(os.path.getsize(self.pcap_file_path)).encode('utf-8'))

            # Add max. first 40000 * 224 bytes = 8,5 MB of file
            buf = afile.read(const_blocksize)
            blocks_read += 1
            while len(buf) > 0 and blocks_read < const_max_blocks_read:
                hasher.update(buf)
                buf = afile.read(const_blocksize)
                blocks_read += 1

        return hasher.hexdigest()

    def get_db_path(self, root_directory: str = os.path.join(os.path.expanduser('~'), 'ID2T_data', 'db')):
        """
        Creates a path based on a hashed directory structure. Derives a hash code by the file's hash and derives
        thereof the database path.

        Code and idea based on:
        http://michaelandrews.typepad.com/the_technical_times/2009/10/creating-a-hashed-directory-structure.html

        :param root_directory: The root directory of the hashed directory structure (optional)
        :return: The full path to the database file
        """

        def hashcode(string_in: str):
            """
            Creates a hashcode of a string, based on Java's hashcode implementation.
            Code based on: http://garage.pimentech.net/libcommonPython_src_python_libcommon_javastringhashcode/

            :param string_in: The string the hashcode should be calculated from
            :return: The hashcode as string
            """
            h = 0
            for c in string_in:
                h = (31 * h + ord(c)) & 0xFFFFFFFF
            return ((h + 0x80000000) & 0xFFFFFFFF) - 0x80000000

        file_hash = self.get_file_hash()
        hashcode = hashcode(file_hash)
        mask = 255
        dir_first_level = hashcode & mask
        dir_second_level = (hashcode >> 8) & mask

        return os.path.join(root_directory, str(dir_first_level), str(dir_second_level), file_hash[0:12] + ".sqlite3")
