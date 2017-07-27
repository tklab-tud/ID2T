/**
 * Class for performing artifacts tests.
 */

#ifndef CPP_ARTIFACTS_TESTS_H
#define CPP_ARTIFACTS_TESTS_H

// Aidmar
//#include <iomanip>

#include <tins/tins.h>
#include <iostream>
//#include <time.h>
#include <stdio.h>
//#include <sys/stat.h>
//#include <unordered_map>
//#include "statistics.h"

#include "utilities.h"

using namespace Tins;

class artifacts_tests {

public:
    /*
    * Class constructor
    */
    artifacts_tests();

    /*
     * Attributes
     */
    int correctChecksum;
    int incorrectChecksum;
    float checksumIncorrectRatio;
    
    int noPayloadCount;
    int payloadCount;
    
    //std::string timstampPrecision;
    
    //statistics stats;
    //std::string filePath;

    /*
     * Methods
     */
    void check_checksum(std::string ipAddressSender, std::string ipAddressReceiver, TCP tcpPkt);
    float get_checksum_incorrect_ratio();
    void check_payload(const PDU *pkt);
    float get_payload_ratio();
    void check_tos(uint8_t ToS);
    //bool check_timestamp_precision(const Packet &pkt);

    /*
    inline bool file_exists(const std::string &filePath);

    long double get_timestamp_mu_sec(const int after_packet_number);

    std::string merge_pcaps(const std::string pcap_path);

    void collect_statistics();

    void write_to_database(std::string database_path);
    */
};


#endif //CPP_ARTIFACTS_TESTS_H
