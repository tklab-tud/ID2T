/**
 * Class writing the statistics to the database.
 */

#ifndef CPP_PCAPREADER_STATISTICSDB_H
#define CPP_PCAPREADER_STATISTICSDB_H

#include <iostream>
#include <memory>
#include <string>
#include "statistics.h"
#include <pybind11/pybind11.h>
#include <SQLiteCpp/SQLiteCpp.h>
#include <unordered_map>

namespace py = pybind11;

class statistics_db {
public:
    /*
     * Constructor: Creates new database / Opens existing database
     */
    statistics_db(std::string database_path, std::string resourcePath);

    /*
     * Database version: Increment number on every change in the C++ code!
     */
    static const int DB_VERSION = 17;

    /*
     * Methods to read from database
     */
    void getNoneExtraTestsInveralStats(std::vector<double>& intervals);

    /*
     * Methods for writing values into database
     */
    void writeStatisticsIP(const std::unordered_map<std::string, entry_ipStat> &ipStatistics);

    void writeStatisticsDegree(const std::unordered_map<std::string, entry_ipStat> &ipStatistics);

    void writeStatisticsTTL(const std::unordered_map<ipAddress_ttl, int> &ttlDistribution);

    void writeStatisticsMSS(const std::unordered_map<ipAddress_mss, int> &mssDistribution);

    void writeStatisticsToS(const std::unordered_map<ipAddress_tos, int> &tosDistribution);

    void writeStatisticsWin(const std::unordered_map<ipAddress_win, int> &winDistribution);

    void writeStatisticsProtocols(const std::unordered_map<ipAddress_protocol, entry_protocolStat> &protocolDistribution);

    void writeStatisticsPorts(const std::unordered_map<ipAddress_inOut_port, entry_portStat> &portsStatistics);

    void writeStatisticsIpMac(const std::unordered_map<std::string, std::string> &IpMacStatistics);

    void writeStatisticsFile(int packetCount, float captureDuration, std::string timestampFirstPkt,
                             std::string timestampLastPkt, float avgPacketRate, float avgPacketSize,
                             float avgPacketsSentPerHost, float avgBandwidthIn, float avgBandwidthOut,
                             bool doExtraTests);

    void writeStatisticsConv(std::unordered_map<conv, entry_convStat> &convStatistics);

    void writeStatisticsConvExt(std::unordered_map<convWithProt, entry_convStatExt> &conv_statistics_extended);

    void writeStatisticsInterval(const std::unordered_map<std::string, entry_intervalStat> &intervalStatistics, std::vector<std::chrono::duration<int, std::micro>> timeInterval, bool del, int defaultInterval, bool extraTests);

    void writeDbVersion();

    void readPortServicesFromNmap();

    void writeStatisticsUnrecognizedPDUs(const std::unordered_map<unrecognized_PDU, unrecognized_PDU_stat> &unrecognized_PDUs);

private:
    // Pointer to the SQLite database
    std::unique_ptr<SQLite::Database> db;

    // Vector which contains all ports and their corresponding services
    std::unordered_map<int, std::string> portServices;

    std::string resourcePath;

};


#endif //CPP_PCAPREADER_STATISTICSDB_H
