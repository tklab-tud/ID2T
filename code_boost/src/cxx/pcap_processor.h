/**
 * Class for processing PCAPs to collect statistical data.
 */

#ifndef CPP_PCAPREADER_MAIN_H
#define CPP_PCAPREADER_MAIN_H

#include <algorithm>
#include <iomanip>
#include <tins/tins.h>
#include <iostream>
#include <pybind11/pybind11.h>
#include <time.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unordered_map>
#include "statistics.h"
#include "statistics_db.h"

namespace py = pybind11;

using namespace Tins;

class pcap_processor {

public:
    /*
    * Class constructor
    */
    pcap_processor(std::string path, std::string extraTests, std::string resource_path);

    /*
     * Attributes
     */
    statistics stats;
    std::string filePath;
    bool hasUnrecognized;
    std::chrono::duration<int, std::micro> timeInterval;

    /*
     * Methods
     */
    inline bool file_exists(const std::string &filePath);

    void process_packets(const Packet &pkt);

    long double get_timestamp_mu_sec(const int after_packet_number);

    std::string merge_pcaps(const std::string pcap_path);

    bool read_pcap_info(const std::string &filePath, std::size_t &totalPakets);

    void collect_statistics(const py::list& intervals);

    void write_to_database(std::string database_path, const py::list& intervals, bool del);

    void write_new_interval_statistics(std::string database_path, const py::list& intervals);

    static int get_db_version() { return statistics_db::DB_VERSION; }
};


#endif //CPP_PCAPREADER_MAIN_H
