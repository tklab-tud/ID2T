/**
 *
 */

#ifndef CPP_PCAPREADER_STATISTICSDB_H
#define CPP_PCAPREADER_STATISTICSDB_H

// Aidmar
#include <iostream>
#include <memory> 

#include <string>
#include "statistics.h"
#include <SQLiteCpp/SQLiteCpp.h>

class statistics_db {
public:
    /*
     * Constructor: Creates new database / Opens existing database
     */
    statistics_db(std::string database_path);

    /*
     * Methods for writing values into database
     */
    void writeStatisticsIP(std::unordered_map<std::string, entry_ipStat> ipStatistics);

    void writeStatisticsTTL(std::unordered_map<ipAddress_ttl, int> ttlDistribution);

    void writeStatisticsProtocols(std::unordered_map<ipAddress_protocol, int> protocolDistribution);

    void writeStatisticsPorts(std::unordered_map<ipAddress_inOut_port, int> portsStatistics);

    void writeStatisticsIpMac(std::unordered_map<std::string, std::string> IpMacStatistics);

    void writeStatisticsMss(std::unordered_map<std::string, int> mssStatistics);

    void writeStatisticsFile(int packetCount, float captureDuration, std::string timestampFirstPkt,
                             std::string timestampLastPkt, float avgPacketRate, float avgPacketSize,
                             float avgPacketsSentPerHost, float avgBandwidthIn, float avgBandwidthOut);

    // Aidmar
    void writeStatisticsMss_dist(std::unordered_map<ipAddress_mss, int> mssDistribution);

private:
    // Pointer to the SQLite database
    std::unique_ptr<SQLite::Database> db;


};


#endif //CPP_PCAPREADER_STATISTICSDB_H
