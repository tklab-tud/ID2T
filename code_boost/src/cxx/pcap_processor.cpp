#include "pcap_processor.h"

using namespace Tins;

/**
 * Creates a new pcap_processor object.
 * @param path The path where the PCAP to get analyzed is locatated.
 */
pcap_processor::pcap_processor(std::string path, std::string extraTests, std::string resource_path, std::string database_path) : stats(resource_path) {
    filePath = path;
    resourcePath = resource_path;
    databasePath = database_path;
    hasUnrecognized = false;
    if(extraTests == "True")
        stats.setDoExtraTests(true);
    else stats.setDoExtraTests(false);
}

/**
 * Iterates over all packets, starting by packet no. 1, and stops if
 * after_packet_number equals the current packet number.
 * @param after_packet_number The packet position in the PCAP file whose timestamp is wanted.
 * @return The timestamp of the last processed packet plus 1 microsecond.
 */
long double pcap_processor::get_timestamp_mu_sec(const int after_packet_number) {
    if (file_exists(filePath)) {
        FileSniffer sniffer(filePath);
        int current_packet = 1;
        for (SnifferIterator i = sniffer.begin(); i != sniffer.end(); i++) {
            if (after_packet_number == current_packet) {
                const Timestamp &ts = i->timestamp();
                return (long double) ((ts.seconds() * 1000000) + ts.microseconds() + 1);
            }
            current_packet++;
        }
    }
    return -1.0;
}

/**
 * Merges two PCAP files, given by paths in filePath and parameter pcap_path.
 * @param pcap_path The path to the file which should be merged with the loaded PCAP file.
 * @return The string containing the file path to the merged PCAP file.
 */
std::string pcap_processor::merge_pcaps(const std::string pcap_path) {
    // Build new filename with timestamp
    // Build timestamp
    time_t curr_time = time(0);
    char buff[1024];
    struct tm *now = localtime(&curr_time);
    strftime(buff, sizeof(buff), "%Y%m%d-%H%M%S", now);
    std::string tstmp(buff);

    // Replace filename with 'timestamp_filename'
    std::string new_filepath = filePath;
    const std::string &newExt = "_" + tstmp + ".pcap";
    std::string::size_type h = new_filepath.rfind('.', new_filepath.length());

    if ((filePath.length() + newExt.length()) < 250) {

        if (h != std::string::npos) {
            new_filepath.replace(h, newExt.length(), newExt);
        } else {
            new_filepath.append(newExt);
        }
    }

    else {
        new_filepath = (new_filepath.substr(0, new_filepath.find('_'))).append(newExt);
    }

    FileSniffer sniffer_base(filePath);
    SnifferIterator iterator_base = sniffer_base.begin();

    FileSniffer sniffer_attack(pcap_path);
    SnifferIterator iterator_attack = sniffer_attack.begin();

    PacketWriter writer(new_filepath, PacketWriter::ETH2);

    bool all_attack_pkts_processed = false;
    // Go through base PCAP and merge packets by timestamp
    for (; iterator_base != sniffer_base.end();) {
        auto tstmp_base = (iterator_base->timestamp().seconds()) + (iterator_base->timestamp().microseconds()*1e-6);
        auto tstmp_attack = (iterator_attack->timestamp().seconds()) + (iterator_attack->timestamp().microseconds()*1e-6);
        if (!all_attack_pkts_processed && tstmp_attack <= tstmp_base) {
            try {
                writer.write(*iterator_attack);
            } catch (serialization_error&) {
                std::cerr << std::setprecision(15) << "Could not serialize attack packet with timestamp " << tstmp_attack << std::endl;
            }
            iterator_attack++;
            if (iterator_attack == sniffer_attack.end())
                all_attack_pkts_processed = true;
        } else {
            try {
                writer.write(*iterator_base);
            } catch (serialization_error&) {
                    std::cerr << "Could not serialize base packet with timestamp " << std::setprecision(15) << tstmp_base << std::endl;
            }
            iterator_base++;
        }
    }

    // This may happen if the base PCAP is smaller than the attack PCAP
    // In this case append the remaining packets of the attack PCAP
    for (; iterator_attack != sniffer_attack.end(); iterator_attack++) {
        try {
            writer.write(*iterator_attack);
        } catch (serialization_error&) {
            auto tstmp_attack = (iterator_attack->timestamp().seconds()) + (iterator_attack->timestamp().microseconds()*1e-6);
            std::cerr << "Could not serialize attack packet with timestamp " << std::setprecision(15) << tstmp_attack << std::endl;
        }
    }
    return new_filepath;
}

bool pcap_processor::read_pcap_info(const std::string &filePath, std::size_t &totalPakets) {
    // libtins has a lot of overhead when just iterating through, so we use libpcap directly
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_open_offline(filePath.c_str(), errbuf);
    if (pcap_handle == nullptr) {
        std::cerr << "ERROR: Could not open PCAP '" << filePath << "': " << errbuf << std::endl;
        return false;
    }

    const u_char *packet;
    pcap_pkthdr header;

    packet = pcap_next(pcap_handle, &header);
    if (packet == nullptr)
    {
        std::cerr << "ERROR: PCAP file is empty!" << std::endl;
        pcap_close(pcap_handle);
        return false;
    }

    // Extract first timestamp
    stats.setTimestampFirstPacket(Tins::Timestamp(header.ts));

    totalPakets = 0;
    timeval lv;
    while (packet != nullptr) {
        totalPakets++;
        // Extract last timestamp
        lv = header.ts;
        packet = pcap_next(pcap_handle, &header);
    }

    stats.setTimestampLastPacket(Tins::Timestamp(lv));

    pcap_close(pcap_handle);
    return true;
}

/**
 * Collect statistics of the loaded PCAP file. Calls for each packet the method process_packets.
 * param: user specified interval in seconds
 */
void pcap_processor::collect_statistics(py::list& intervals) {
    // Only process PCAP if file exists
    if (file_exists(filePath)) {
        std::cout << "Loading pcap..." << std::endl;
        FileSniffer sniffer(filePath);

        SnifferIterator i = sniffer.begin();
        std::chrono::microseconds currentPktTimestamp;

        // Read PCAP file info
        std::size_t totalPackets = 0;
        if (!read_pcap_info(filePath, totalPackets)) return;

        // choose a suitable time interval
        int timeIntervalCounter = 1;
        long timeInterval_microsec = 0;
        std::vector<std::chrono::microseconds> intervalStartTimestamp;
        std::chrono::microseconds firstTimestamp = stats.getTimestampFirstPacket();

        std::vector<std::chrono::duration<int, std::micro>> timeIntervals;
        std::vector<std::chrono::microseconds> barriers;

        std::vector<double> intervals_vec;
        for (auto interval: intervals) {
            intervals_vec.push_back(interval.cast<double>());
        }

        if (intervals_vec.size() == 0 || intervals_vec[0] == 0) {
            int timeIntervalsNum = 100;
            std::chrono::microseconds lastTimestamp = stats.getTimestampLastPacket();
            std::chrono::microseconds captureDuration = lastTimestamp - firstTimestamp;
            if(captureDuration.count()<=0){
                std::cerr << "ERROR: PCAP file is empty!" << std::endl;
                return;
            }
            timeInterval_microsec = captureDuration.count() / timeIntervalsNum;
            stats.setDefaultInterval(static_cast<int>(timeInterval_microsec));
            intervalStartTimestamp.push_back(firstTimestamp);
            std::chrono::duration<int, std::micro> timeInterval(timeInterval_microsec);
            std::chrono::microseconds barrier = timeInterval;
            timeIntervals.push_back(timeInterval);
            barriers.push_back(barrier);
        } else {
            if (stats.getDoExtraTests()) {
                statistics_db stats_db(databasePath, resourcePath);
                stats_db.getNoneExtraTestsInveralStats(intervals_vec);
            }
            for (auto interval: intervals_vec) {
                timeInterval_microsec = static_cast<long>(interval * 1000000);
                intervalStartTimestamp.push_back(firstTimestamp);
                std::chrono::duration<int, std::micro> timeInterval(timeInterval_microsec);
                std::chrono::microseconds barrier = timeInterval;
                timeIntervals.push_back(timeInterval);
                barriers.push_back(barrier);
            }
        }

        std::sort(timeIntervals.begin(), timeIntervals.end());
        std::sort(barriers.begin(), barriers.end());

        std::cout << std::endl;
        std::chrono::system_clock::time_point lastPrinted = std::chrono::system_clock::now();

        int barrier_count = static_cast<int>(barriers.size());

        // Iterate over all packets and collect statistics
        for (; i != sniffer.end(); i++) {
            currentPktTimestamp = i->timestamp();
            std::chrono::microseconds currentDuration = currentPktTimestamp - firstTimestamp;

            // For each interval
            // drops last interval too small
            for (int j = 0; j < barrier_count; j++) {
                if(currentDuration>barriers[j]){
                    stats.addIntervalStat(timeIntervals[j], intervalStartTimestamp[j], currentPktTimestamp);
                    timeIntervalCounter++;

                    barriers[j] =  barriers[j] + timeIntervals[j];
                    intervalStartTimestamp[j] = currentPktTimestamp;
                }
            }

            stats.incrementPacketCount();
            this->process_packets(*i);

            // Indicate progress once every second
            if (std::chrono::system_clock::now() - lastPrinted >= std::chrono::seconds(1)) {
                int packetCount = stats.getPacketCount();
                std::cout << "\rInspected packets: ";
                std::cout << std::fixed << std::setprecision(1) << (static_cast<float>(packetCount)*100/totalPackets) << "%";
                std::cout << " (" << packetCount << "/" << totalPackets << ")" << std::flush;
                lastPrinted = std::chrono::system_clock::now();

                if (PyErr_CheckSignals()) throw py::error_already_set();
            }
        }

        std::cout << "\rInspected packets: ";
        std::cout << "100.0% (" << totalPackets << "/" << totalPackets << ")" << std::endl;

        // Save timestamp of last packet into statistics
        stats.setTimestampLastPacket(currentPktTimestamp);

        // Create the communication interval statistics from the gathered communication intervals within every extended conversation statistic
        stats.createCommIntervalStats();

        if(hasUnrecognized) {
            std::cout << "Unrecognized PDUs detected: Check 'unrecognized_pdus' table!" << std::endl;
        }
    }
}

/**
 * Analyzes a given packet and collects statistical information.
 * @param pkt The packet to get analyzed.
 */
void pcap_processor::process_packets(const Packet &pkt) {
    // Layer 2: Data Link Layer ------------------------
    std::string macAddressSender;
    std::string macAddressReceiver;
    const PDU *pdu_l2 = pkt.pdu();
    uint32_t sizeCurrentPacket = pdu_l2->size();

    // Layer 3 - Network -------------------------------
    const PDU *pdu_l3 = pkt.pdu()->inner_pdu();
    const PDU::PDUType pdu_l3_type = pdu_l3->pdu_type();
    std::string ipAddressSender;
    std::string ipAddressReceiver;

    if (pdu_l2->pdu_type() == PDU::ETHERNET_II) {
        const EthernetII &eth = (const EthernetII &) *pdu_l2;
        macAddressSender = eth.src_addr().to_string();
        macAddressReceiver = eth.dst_addr().to_string();
        sizeCurrentPacket = eth.size();
    }

    /*if (pdu_l2->pdu_type() == PDU::ARP || pdu_l3->pdu_type() == PDU::ARP) {
        const ARP &arp = pdu_l2->rfind_pdu<ARP>();
        std::string ipAddressTarget = arp.target_ip_addr().to_string();
        std::string macAddressTarget = arp.target_hw_addr().to_string();
    }*/

    stats.addPacketSize(sizeCurrentPacket);

    // PDU is IPv4
    if (pdu_l3_type == PDU::PDUType::IP) {
        const IP &ipLayer = (const IP &) *pdu_l3;
        ipAddressSender = ipLayer.src_addr().to_string();
        ipAddressReceiver = ipLayer.dst_addr().to_string();

        if (macAddressReceiver=="ff:ff:ff:ff:ff:ff")
            stats.assignBroadcastMacAddress(ipAddressReceiver, macAddressReceiver);

        // IP distribution
        stats.addIpStat_packetSent(ipAddressSender, ipAddressReceiver, sizeCurrentPacket, pkt.timestamp());

        // TTL distribution
        stats.incrementTTLcount(ipAddressSender, ipLayer.ttl());

        // ToS distribution
        stats.incrementToScount(ipAddressSender, ipLayer.tos());

        // Protocol distribution
        stats.incrementProtocolCount(ipAddressSender, "IPv4");
        stats.increaseProtocolByteCount(ipAddressSender, "IPv4", sizeCurrentPacket);

        // Assign IP Address to MAC Address
        stats.assignMacAddress(ipAddressSender, macAddressSender);
        if (!stats.isBroadcastAddress(ipAddressReceiver))
            stats.assignMacAddress(ipAddressReceiver, macAddressReceiver);

    /*} // PDU is IPv6
    // FIXME: IPv6 Workaround
    else if (pdu_l3_type == PDU::PDUType::IPv6) {
        return;
        const IPv6 &ipLayer = (const IPv6 &) *pdu_l3;
        ipAddressSender = ipLayer.src_addr().to_string();
        ipAddressReceiver = ipLayer.dst_addr().to_string();

        // IP distribution
        stats.addIpStat_packetSent(ipAddressSender, ipAddressReceiver, sizeCurrentPacket, pkt.timestamp());

        // TTL distribution
        stats.incrementTTLcount(ipAddressSender, ipLayer.hop_limit());

        // Protocol distribution
        stats.incrementProtocolCount(ipAddressSender, "IPv6");
        stats.increaseProtocolByteCount(ipAddressSender, "IPv6", sizeCurrentPacket);

        // Assign IP Address to MAC Address
        stats.assignMacAddress(ipAddressSender, macAddressSender);
        stats.assignMacAddress(ipAddressReceiver, macAddressReceiver);
    */
    //PDU is unrecognized
    } else {
        hasUnrecognized = true;

        const EthernetII &eth = (const EthernetII &) *pdu_l2;
        Tins::Timestamp ts = pkt.timestamp();
        std::string timestamp_pkt = stats.getFormattedTimestamp(ts.seconds(), ts.microseconds());

        stats.incrementUnrecognizedPDUCount(macAddressSender, macAddressReceiver, eth.payload_type(), timestamp_pkt);
    }

    // Layer 4 - Transport -------------------------------
    const PDU *pdu_l4 = pdu_l3->inner_pdu();
    if (pdu_l4 != 0) {
        // Protocol distribution - layer 4
        PDU::PDUType p = pdu_l4->pdu_type();

        // Check for IPv4: payload
        if (pdu_l3_type == PDU::PDUType::IP) {
            stats.checkPayload(pdu_l4);
          }

        if (p == PDU::PDUType::TCP) {
            const TCP &tcpPkt = (const TCP &) *pdu_l4;
            
            // Check TCP checksum
            if (pdu_l3_type == PDU::PDUType::IP) {
                stats.checkTCPChecksum(ipAddressSender, ipAddressReceiver, tcpPkt);
            }

            stats.incrementProtocolCount(ipAddressSender, "TCP");
            stats.increaseProtocolByteCount(ipAddressSender, "TCP", sizeCurrentPacket);

            // Conversation statistics
            const TCP& tcp = pdu_l4->rfind_pdu<TCP>();
            stats.addConvStat(ipAddressSender, tcpPkt.sport(), ipAddressReceiver, tcpPkt.dport(), pkt.timestamp(), tcp.flags());
            stats.addConvStatExt(ipAddressSender,tcpPkt.sport(), ipAddressReceiver, tcpPkt.dport(), "TCP", pkt.timestamp());

            // Window Size distribution
            int win = tcpPkt.window();
            stats.incrementWinCount(ipAddressSender, win);

            // MSS distribution
            auto mssOption = tcpPkt.search_option(TCP::MSS);
            if (mssOption != nullptr) {
                auto mss_value = mssOption->to<uint16_t>();
                stats.incrementMSScount(ipAddressSender, mss_value);
            }

            stats.incrementPortCount(ipAddressSender, tcpPkt.sport(), ipAddressReceiver, tcpPkt.dport(), "TCP");
            stats.increasePortByteCount(ipAddressSender, tcpPkt.sport(), ipAddressReceiver, tcpPkt.dport(), sizeCurrentPacket, "TCP");

          // UDP Packet
        } else if (p == PDU::PDUType::UDP) {
            const UDP &udpPkt = (const UDP &) *pdu_l4;
            stats.incrementProtocolCount(ipAddressSender, "UDP");
            stats.increaseProtocolByteCount(ipAddressSender, "UDP", sizeCurrentPacket);
            stats.incrementPortCount(ipAddressSender, udpPkt.sport(), ipAddressReceiver, udpPkt.dport(), "UDP");
            stats.increasePortByteCount(ipAddressSender, udpPkt.sport(), ipAddressReceiver, udpPkt.dport(), sizeCurrentPacket, "UDP");
            //TODO: (optional) add udp flag support?
            stats.addConvStatExt(ipAddressSender,udpPkt.sport(), ipAddressReceiver, udpPkt.dport(), "UDP", pkt.timestamp());
        } else if (p == PDU::PDUType::ICMP) {
            stats.incrementProtocolCount(ipAddressSender, "ICMP");
            stats.increaseProtocolByteCount(ipAddressSender, "ICMP", sizeCurrentPacket);
        } else if (p == PDU::PDUType::ICMPv6) {
            stats.incrementProtocolCount(ipAddressSender, "ICMPv6");
            stats.increaseProtocolByteCount(ipAddressSender, "ICMPv6", sizeCurrentPacket);
        }
    }
}

/**
 * Writes the collected statistic data into a SQLite3 database located at database_path. Uses an existing
 * database or, if not present, creates a new database.
 * @param database_path The path to the database file, ending with .sqlite3.
 */
void pcap_processor::write_to_database(std::string database_path, const py::list& intervals, bool del) {
    std::vector<std::chrono::duration<int, std::micro>> timeIntervals;
    std::vector<double> intervals_vec;
    for (auto interval: intervals) {
        intervals_vec.push_back(interval.cast<double>());
    }
    if (stats.getDoExtraTests()) {
        statistics_db stats_db(databasePath, resourcePath);
        stats_db.getNoneExtraTestsInveralStats(intervals_vec);
    }
    for (auto interval: intervals_vec) {
        std::chrono::duration<int, std::micro> timeInterval(static_cast<long>(interval * 1000000));
        timeIntervals.push_back(timeInterval);
    }
    stats.writeToDatabase(database_path, timeIntervals, del);
}

void pcap_processor::write_new_interval_statistics(std::string database_path, const py::list& intervals) {
    std::vector<std::chrono::duration<int, std::micro>> timeIntervals;
    std::vector<double> intervals_vec;
    for (auto interval: intervals) {
        intervals_vec.push_back(interval.cast<double>());
    }
    if (stats.getDoExtraTests()) {
        statistics_db stats_db(databasePath, resourcePath);
        stats_db.getNoneExtraTestsInveralStats(intervals_vec);
    }
    for (auto interval: intervals_vec) {
        std::chrono::duration<int, std::micro> timeInterval(static_cast<long>(interval * 1000000));
        timeIntervals.push_back(timeInterval);
    }
    stats.writeIntervalsToDatabase(database_path, timeIntervals, false);
}

/**
 * Checks whether the file with the given file path exists.
 * @param filePath The path to the file to check.
 * @return True iff the file exists, otherweise False.
 */
bool inline pcap_processor::file_exists(const std::string &filePath) {
    struct stat buffer;
    return stat(filePath.c_str(), &buffer) == 0;
}

/*
 * Comment in if executable should be build & run
 * Comment out if library should be build
 */
//int main() {
//    std::cout << "Starting application." << std::endl;
//    pcap_processor pcap = pcap_processor("/home/anonymous/Downloads/ID2T-toolkit/captures/col/capture_1.pcap", "True");
//
//    long double t = pcap.get_timestamp_mu_sec(87);
//    std::cout << t << std::endl;
//
//    time_t start, end;
//    time(&start);
//    pcap.collect_statistics();
//    time(&end);
//    double dif = difftime(end, start);
//    printf("Elapsed time is %.2lf seconds.", dif);
//    pcap.stats.writeToDatabase("/home/anonymous/Downloads/myDB.sqlite3");
//
//    //std::string path = pcap.merge_pcaps("/tmp/tmp0okkfdx_");
//    //std::cout << path << std::endl;
//
//    return 0;
//}

/*
 * Comment out if executable should be build & run
 * Comment in if library should be build
 */
PYBIND11_MODULE (libpcapreader, m) {
    py::class_<pcap_processor>(m, "pcap_processor")
            .def(py::init<std::string, std::string, std::string, std::string>())
            .def("merge_pcaps", &pcap_processor::merge_pcaps)
            .def("collect_statistics", &pcap_processor::collect_statistics)
            .def("get_timestamp_mu_sec", &pcap_processor::get_timestamp_mu_sec)
            .def("write_to_database", &pcap_processor::write_to_database)
            .def("write_new_interval_statistics", &pcap_processor::write_new_interval_statistics)
            .def_static("get_db_version", &pcap_processor::get_db_version);
}
