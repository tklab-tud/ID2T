# import libpcapreader as pr
import release_test.libpcapreader as pr
import operator

pcap = pr.pcap_processor("/mnt/hgfs/datasets/95M.pcap")

# target=open(file.getFilePath()+".stat", 'w')
# target.truncate()

pcap.collect_statistics()
#print( pcap.get_timestamp_mu_sec(87) )

# filepath_mergedPcap = pcap.merge_pcaps("/mnt/hgfs/datasets/PcapExamples/LDAP.pcap")
#print(filepath_mergedPcap)

pcap.write_to_database("/home/pjattke/myDB.sqlite3")
