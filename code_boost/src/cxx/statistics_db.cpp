#include "statistics_db.h"
#include <iostream>
#include <sstream>

/**
 * Creates a new statistics_db object. Opens an existing database located at database_path. If not existing, creates
 * a new database at database_path.
 * @param database_path The file path of the database.
 */
statistics_db::statistics_db(std::string database_path) {
    // Append file extension if not present
    if (database_path.find(".sqlite3") == database_path.npos) {
        database_path += ".sqlite3";
    }
    // creates the DB if not existing, opens the DB for read+write access
    db.reset(new SQLite::Database(database_path, SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE));
}

/**
 * Writes the IP statistics into the database.
 * @param ipStatistics The IP statistics from class statistics.
 */
void statistics_db::writeStatisticsIP(std::unordered_map<std::string, entry_ipStat> ipStatistics) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_statistics");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_statistics ( "
                "ipAddress TEXT, "
                "pktsReceived INTEGER, "
                "pktsSent INTEGER, "
                "kbytesReceived REAL, "
                "kbytesSent REAL, "
                "PRIMARY KEY(ipAddress));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_statistics VALUES (?, ?, ?, ?, ?)");
        for (auto it = ipStatistics.begin(); it != ipStatistics.end(); ++it) {
            entry_ipStat e = it->second;
            query.bind(1, it->first);
            query.bind(2, (int) e.pkts_received);
            query.bind(3, (int) e.pkts_sent);
            query.bind(4, e.kbytes_received);
            query.bind(5, e.kbytes_sent);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

/**
 * Writes the TTL distribution into the database.
 * @param ttlDistribution The TTL distribution from class statistics.
 */
void statistics_db::writeStatisticsTTL(std::unordered_map<ipAddress_ttl, int> ttlDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_ttl");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_ttl ("
                "ipAddress TEXT,"
                "ttlValue INTEGER,"
                "ttlCount INTEGER,"
                "PRIMARY KEY(ipAddress,ttlValue));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_ttl VALUES (?, ?, ?)");
        for (auto it = ttlDistribution.begin(); it != ttlDistribution.end(); ++it) {
            ipAddress_ttl e = it->first;
            query.bind(1, e.ipAddress);
            query.bind(2, e.ttlValue);
            query.bind(3, it->second);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

/**
 * Writes the protocol distribution into the database.
 * @param protocolDistribution The protocol distribution from class statistics.
 */
void statistics_db::writeStatisticsProtocols(std::unordered_map<ipAddress_protocol, int> protocolDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_protocols");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_protocols ("
                "ipAddress TEXT,"
                "protocolName TEXT,"
                "protocolCount INTEGER,"
                "PRIMARY KEY(ipAddress,protocolName));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_protocols VALUES (?, ?, ?)");
        for (auto it = protocolDistribution.begin(); it != protocolDistribution.end(); ++it) {
            ipAddress_protocol e = it->first;
            query.bind(1, e.ipAddress);
            query.bind(2, e.protocol);
            query.bind(3, it->second);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

/**
 * Writes the port statistics into the database.
 * @param portsStatistics The ports statistics from class statistics.
 */
void statistics_db::writeStatisticsPorts(std::unordered_map<ipAddress_inOut_port, int> portsStatistics) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_ports");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_ports ("
                "ipAddress TEXT,"
                "portDirection TEXT,"
                "portNumber INTEGER,"
                "portCount INTEGER,"
                "PRIMARY KEY(ipAddress,portDirection,portNumber));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_ports VALUES (?, ?, ?, ?)");
        for (auto it = portsStatistics.begin(); it != portsStatistics.end(); ++it) {
            ipAddress_inOut_port e = it->first;
            query.bind(1, e.ipAddress);
            query.bind(2, e.trafficDirection);
            query.bind(3, e.portNumber);
            query.bind(4, it->second);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

/**
 *  Writes the IP address -> MAC address mapping into the database.
 * @param IpMacStatistics The IP address -> MAC address mapping from class statistics.
 */
void statistics_db::writeStatisticsIpMac(std::unordered_map<std::string, std::string> IpMacStatistics) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_mac");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_mac ("
                "ipAddress TEXT,"
                "macAddress TEXT,"
                "PRIMARY KEY(ipAddress));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_mac VALUES (?, ?)");
        for (auto it = IpMacStatistics.begin(); it != IpMacStatistics.end(); ++it) {
            query.bind(1, it->first);
            query.bind(2, it->second);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

/**
 * Writes the MSS statistics into the database.
 * @param mssStatistics The MSS statistics from class statistics.
 */
void statistics_db::writeStatisticsMss(std::unordered_map<std::string, int> mssStatistics) {
    try {
        db->exec("DROP TABLE IF EXISTS tcp_mss");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE tcp_mss ("
                "ipAddress TEXT,"
                "mss INTEGER);";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO tcp_mss VALUES (?, ?)");
        for (auto it = mssStatistics.begin(); it != mssStatistics.end(); ++it) {
            query.bind(1, it->first);
            query.bind(2, it->second);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

/**
 * Writes general file statistics into the database.
 * @param packetCount The number of packets in the PCAP file.
 * @param captureDuration The duration of the capture (format: SS.mmmmmm).
 * @param timestampFirstPkt The timestamp of the first packet in the PCAP file.
 * @param timestampLastPkt The timestamp of the last packet in the PCAP file.
 * @param avgPacketRate The average packet rate (#packets / capture duration).
 * @param avgPacketSize The average packet size.
 * @param avgPacketsSentPerHost The average packets sent per host.
 * @param avgBandwidthIn The average incoming bandwidth.
 * @param avgBandwidthOut The average outgoing bandwidth.
 */
void statistics_db::writeStatisticsFile(int packetCount, float captureDuration, std::string timestampFirstPkt,
                                        std::string timestampLastPkt, float avgPacketRate, float avgPacketSize,
                                        float avgPacketsSentPerHost, float avgBandwidthIn, float avgBandwidthOut) {
    try {
        db->exec("DROP TABLE IF EXISTS file_statistics");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE file_statistics ("
                "packetCount	INTEGER,"
                "captureDuration TEXT,"
                "timestampFirstPacket TEXT,"
                "timestampLastPacket TEXT,"
                "avgPacketRate REAL,"
                "avgPacketSize REAL,"
                "avgPacketsSentPerHost REAL,"
                "avgBandwidthIn REAL,"
                "avgBandwidthOut REAL);";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO file_statistics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        query.bind(1, packetCount);
        query.bind(2, captureDuration);
        query.bind(3, timestampFirstPkt);
        query.bind(4, timestampLastPkt);
        query.bind(5, avgPacketRate);
        query.bind(6, avgPacketSize);
        query.bind(7, avgPacketsSentPerHost);
        query.bind(8, avgBandwidthIn);
        query.bind(9, avgBandwidthOut);
        query.exec();
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

// Aidamr
/**
 * Writes the MSS distribution into the database.
 * @param mssDistribution The MSS distribution from class statistics.
 */
void statistics_db::writeStatisticsMss_dist(std::unordered_map<ipAddress_mss, int> mssDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS tcp_mss_dist");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE tcp_mss_dist ("
                "ipAddress TEXT,"
                "mssValue INTEGER,"
                "mssCount INTEGER,"
                "PRIMARY KEY(ipAddress,mssValue));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO tcp_mss_dist VALUES (?, ?, ?)");
        for (auto it = mssDistribution.begin(); it != mssDistribution.end(); ++it) {
            ipAddress_mss e = it->first;
            query.bind(1, e.ipAddress);
            query.bind(2, e.mssValue);
            query.bind(3, it->second);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

// Aidamr
/**
 * Writes the window size distribution into the database.
 * @param winDistribution The window size distribution from class statistics.
 */
void statistics_db::writeStatisticsWin(std::unordered_map<ipAddress_win, int> winDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS tcp_syn_win");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE tcp_syn_win ("
                "ipAddress TEXT,"
                "winSize INTEGER,"
                "winCount INTEGER,"
                "PRIMARY KEY(ipAddress,winSize));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO tcp_syn_win VALUES (?, ?, ?)");
        for (auto it = winDistribution.begin(); it != winDistribution.end(); ++it) {
            ipAddress_win e = it->first;
            query.bind(1, e.ipAddress);
            query.bind(2, e.winSize);
            query.bind(3, it->second);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

// Aidamr
/**
 * Writes the flow statistics into the database.
 * @param flowStatistics The flow from class statistics.
 */
void statistics_db::writeStatisticsFlow(std::unordered_map<flow, entry_flowStat> flowStatistics){          
    try {
        db->exec("DROP TABLE IF EXISTS flow_statistics");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE flow_statistics ("
                "ipAddressA TEXT,"
                "portA INTEGER,"
                "ipAddressB TEXT,"              
                "portB INTEGER,"
                "pkts_A_B INTEGER,"
                "pkts_B_A INTEGER,"
                "medianDelay INTEGER,"
                //"medianDelay TEXT,"
                "PRIMARY KEY(ipAddressA,portA,ipAddressB,portB));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO flow_statistics VALUES (?, ?, ?, ?, ?, ?, ?)");
        for (auto it = flowStatistics.begin(); it != flowStatistics.end(); ++it) {
            flow f = it->first;
            entry_flowStat e = it->second;
            
            // Compute the median delay
            e.median_delay = e.pkts_delay[e.pkts_delay.size()/2];
            
            query.bind(1, f.ipAddressA);
            query.bind(2, f.portA);
            query.bind(3, f.ipAddressB);
            query.bind(4, f.portB);
            query.bind(5, (int) e.pkts_A_B);
            query.bind(6, (int) e.pkts_B_A);
            query.bind(7, (int) e.median_delay.count());
            //query.bind(7,  std::to_string(e.median_delay.count()));            
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}
