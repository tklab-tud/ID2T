#include "statistics_db.h"
#include <math.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <stdio.h>

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

    // Read ports and services into portServices vector
    readPortServicesFromNmap();
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
                "maxPktRate REAL,"
                "minPktRate REAL,"
                "ipClass TEXT COLLATE NOCASE, "
                "PRIMARY KEY(ipAddress));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_statistics VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        for (auto it = ipStatistics.begin(); it != ipStatistics.end(); ++it) {
            entry_ipStat e = it->second;
            query.bind(1, it->first);
            query.bind(2, (int) e.pkts_received);
            query.bind(3, (int) e.pkts_sent);
            query.bind(4, e.kbytes_received);
            query.bind(5, e.kbytes_sent);
            query.bind(6, e.max_interval_pkt_rate);
            query.bind(7, e.min_interval_pkt_rate);
            query.bind(8, e.ip_class);
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
 * Writes the MSS distribution into the database.
 * @param mssDistribution The MSS distribution from class statistics.
 */
void statistics_db::writeStatisticsMSS(std::unordered_map<ipAddress_mss, int> mssDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS tcp_mss");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE tcp_mss ("
                "ipAddress TEXT,"
                "mssValue INTEGER,"
                "mssCount INTEGER,"
                "PRIMARY KEY(ipAddress,mssValue));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO tcp_mss VALUES (?, ?, ?)");
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

/**
 * Writes the ToS distribution into the database.
 * @param tosDistribution The ToS distribution from class statistics.
 */
void statistics_db::writeStatisticsToS(std::unordered_map<ipAddress_tos, int> tosDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_tos");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_tos ("
                "ipAddress TEXT,"
                "tosValue INTEGER,"
                "tosCount INTEGER,"
                "PRIMARY KEY(ipAddress,tosValue));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_tos VALUES (?, ?, ?)");
        for (auto it = tosDistribution.begin(); it != tosDistribution.end(); ++it) {
            ipAddress_tos e = it->first;
            query.bind(1, e.ipAddress);
            query.bind(2, e.tosValue);
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
 * Writes the window size distribution into the database.
 * @param winDistribution The window size distribution from class statistics.
 */
void statistics_db::writeStatisticsWin(std::unordered_map<ipAddress_win, int> winDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS tcp_win");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE tcp_win ("
                "ipAddress TEXT,"
                "winSize INTEGER,"
                "winCount INTEGER,"
                "PRIMARY KEY(ipAddress,winSize));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO tcp_win VALUES (?, ?, ?)");
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

/**
 * Writes the protocol distribution into the database.
 * @param protocolDistribution The protocol distribution from class statistics.
 */
void statistics_db::writeStatisticsProtocols(std::unordered_map<ipAddress_protocol, entry_protocolStat> protocolDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_protocols");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_protocols ("
                "ipAddress TEXT,"
                "protocolName TEXT COLLATE NOCASE,"
                "protocolCount INTEGER,"
                "byteCount REAL,"
                "PRIMARY KEY(ipAddress,protocolName));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_protocols VALUES (?, ?, ?, ?)");
        for (auto it = protocolDistribution.begin(); it != protocolDistribution.end(); ++it) {
            ipAddress_protocol e = it->first;
            query.bind(1, e.ipAddress);
            query.bind(2, e.protocol);
            query.bind(3, it->second.count);
            query.bind(4, it->second.byteCount);
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
void statistics_db::writeStatisticsPorts(std::unordered_map<ipAddress_inOut_port, entry_portStat> portsStatistics) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_ports");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_ports ("
                "ipAddress TEXT,"
                "portDirection TEXT COLLATE NOCASE,"
                "portNumber INTEGER,"
                "portCount INTEGER,"
                "byteCount REAL,"
                "portProtocol TEXT COLLATE NOCASE,"
                "portService TEXT COLLATE NOCASE,"
                "PRIMARY KEY(ipAddress,portDirection,portNumber));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_ports VALUES (?, ?, ?, ?, ?, ?, ?)");
        for (auto it = portsStatistics.begin(); it != portsStatistics.end(); ++it) {
            ipAddress_inOut_port e = it->first;

            std::string portService = portServices[e.portNumber];
            if(portService.empty()) {portService = "unknown";}

            query.bind(1, e.ipAddress);
            query.bind(2, e.trafficDirection);
            query.bind(3, e.portNumber);
            query.bind(4, it->second.count);
            query.bind(5, it->second.byteCount);
            query.bind(6, e.protocol);
            query.bind(7, portService);
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
                "macAddress TEXT COLLATE NOCASE,"
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


/**
 * Writes the conversation statistics into the database.
 * @param convStatistics The conversation from class statistics.
 */
void statistics_db::writeStatisticsConv(std::unordered_map<conv, entry_convStat> convStatistics){          
    try {
        db->exec("DROP TABLE IF EXISTS conv_statistics");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE conv_statistics ("
                "ipAddressA TEXT,"
                "portA INTEGER,"
                "ipAddressB TEXT,"              
                "portB INTEGER,"
                "pktsCount INTEGER,"
                "avgPktRate REAL,"
                "avgDelay INTEGER,"
                "minDelay INTEGER,"
                "maxDelay INTEGER,"
                "PRIMARY KEY(ipAddressA,portA,ipAddressB,portB));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO conv_statistics VALUES (?, ?, ?, ?, ?,  ?, ?, ?, ?)");

        // Calculate average of inter-arrival times and average packet rate
        for (auto it = convStatistics.begin(); it != convStatistics.end(); ++it) {
            conv f = it->first;
            entry_convStat e = it->second;
            if (e.pkts_count > 1){
                int sumDelay = 0;
                int minDelay = -1;
                int maxDelay = -1;
                for (int i = 0; (unsigned) i < e.interarrival_time.size(); i++) {
                    sumDelay += e.interarrival_time[i].count();
                    if (maxDelay < e.interarrival_time[i].count())
                        maxDelay = e.interarrival_time[i].count();
                    if (minDelay > e.interarrival_time[i].count() || minDelay == -1)
                        minDelay = e.interarrival_time[i].count();
                }
                if (e.interarrival_time.size() > 0)
                    e.avg_interarrival_time = (std::chrono::microseconds) sumDelay / e.interarrival_time.size(); // average
                else e.avg_interarrival_time = (std::chrono::microseconds) 0;

                std::chrono::microseconds start_timesttamp = e.pkts_timestamp[0];
                std::chrono::microseconds end_timesttamp = e.pkts_timestamp.back();
                std::chrono::microseconds conn_duration = end_timesttamp - start_timesttamp;
                e.avg_pkt_rate = (float) e.pkts_count * 1000000 / conn_duration.count(); // pkt per sec

                query.bind(1, f.ipAddressA);
                query.bind(2, f.portA);
                query.bind(3, f.ipAddressB);
                query.bind(4, f.portB);
                query.bind(5, (int) e.pkts_count);
                query.bind(6, (float) e.avg_pkt_rate);
                query.bind(7, (int) e.avg_interarrival_time.count());
                query.bind(8, minDelay);
                query.bind(9, maxDelay);
                query.exec();
                query.reset();
            }
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

/**
 * Writes the interval statistics into the database.
 * @param intervalStatistics The interval entries from class statistics.
 */
void statistics_db::writeStatisticsInterval(std::unordered_map<std::string, entry_intervalStat> intervalStatistics){          
    try {        
        db->exec("DROP TABLE IF EXISTS interval_statistics");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE interval_statistics ("
                "lastPktTimestamp TEXT,"
                "pktsCount INTEGER,"
                "kBytes REAL,"
                "ipSrcEntropy REAL,"      
                "ipDstEntropy REAL,"  
                "ipSrcCumEntropy REAL,"      
                "ipDstCumEntropy REAL,"
                "payloadCount INTEGER,"
                "incorrectTCPChecksumCount INTEGER,"
                "correctTCPChecksumCount INTEGER,"
                "newIPCount INTEGER,"
                "newPortCount INTEGER,"
                "newTTLCount INTEGER,"
                "newWinSizeCount INTEGER,"
                "newToSCount INTEGER,"
                "newMSSCount INTEGER,"
                "PRIMARY KEY(lastPktTimestamp));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO interval_statistics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        for (auto it = intervalStatistics.begin(); it != intervalStatistics.end(); ++it) {
            std::string t = it->first;
            entry_intervalStat e = it->second;        
            
            query.bind(1, t);
            query.bind(2, (int)e.pkts_count);
            query.bind(3, e.kbytes);
            query.bind(4, e.ip_src_entropy);
            query.bind(5, e.ip_dst_entropy);
            query.bind(6, e.ip_src_cum_entropy);
            query.bind(7, e.ip_dst_cum_entropy);
            query.bind(8, e.payload_count);
            query.bind(9, e.incorrect_tcp_checksum_count);
            query.bind(10, e.correct_tcp_checksum_count);
            query.bind(11, e.novel_ip_count);
            query.bind(12, e.novel_port_count);
            query.bind(13, e.novel_ttl_count);
            query.bind(14, e.novel_win_size_count);
            query.bind(15, e.novel_tos_count);
            query.bind(16, e.novel_mss_count);
            query.exec();
            query.reset();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

void statistics_db::writeDbVersion(){
	try {
		SQLite::Transaction transaction(*db);
		SQLite::Statement query(*db, std::string("PRAGMA user_version = ") + std::to_string(DB_VERSION) + ";");
		query.exec();
		transaction.commit();
	}
	catch (std::exception &e) {
        std::cout << "Exception in statistics_db: " << e.what() << std::endl;
    }
}

/**
 * Reads all ports and their corresponding services from nmap-services-tcp.csv and stores them into portServices vector.
 */
void statistics_db::readPortServicesFromNmap()
{
    std::string portnumber;
    std::string service;
    std::string dump;
    std::string nmapPath = getNmapPath();
    std::ifstream reader;

    reader.open(nmapPath, std::ios::in);

    if(reader.is_open())
    {
        getline(reader, dump);

        while(!reader.eof())
        {
            getline(reader, portnumber, ',');
            getline(reader, service, ',');
            getline(reader, dump);
            if(!service.empty() && !portnumber.empty())
            {
                portServices.insert({std::stoi(portnumber), service});
            }
        }

        reader.close();
    }

    else
    {
        std::cerr << "WARNING: " << nmapPath << " could not be opened! PortServices can't be read!" << std::endl;
        portServices.insert({0, "unknown"});
    }
}

/**
 * Gets the path to nmap-services-tcp.csv and makes sure the file is reached from any working directory within "/code"
 * because the working directory can be different when running tests. Checks if the file/path exists and warns the user.
 */
std::string statistics_db::getNmapPath()
{
    //The different working directory paths according to how the database is built:
    //<ID2T> stands for the directory id2t.sh is located in
    //From tests(e.g. pycharm)  /<ID2T>/code/Test
    //From run_tests.sh         /<ID2T>/code
    //From id2t.sh              /<ID2T>
    std::string filename = "nmap-services-tcp.csv";
    std::string resourcesDir = "/resources/";
    std::string codeDir = "/code";
    std::string testDir = "/code/Test";
    char buff[FILENAME_MAX];
    // Working directory
    std::string dir(getcwd(buff, FILENAME_MAX));

    // Check if working directory is id2t.sh directory(try to reach file from working directory)
    if(pathExists(dir + resourcesDir + filename))
    {
        return dir + resourcesDir + filename;
    }

    // If working directory is test directory(happens if tests are called from pycharm for example)
    else if(dir.rfind(testDir) == (dir.size()-testDir.size()))
    {
        // Remove test directory from path
        dir = dir.substr(0, (dir.size()-testDir.size()));
    }

    // If working directory is code directory(happens if tests are called with testscript)
    else if(dir.rfind(codeDir) == (dir.size()-codeDir.size()))
    {
        // Remove code directory from path
        dir = dir.substr(0, (dir.size()-codeDir.size()));
    }

    dir = dir + resourcesDir + filename;

    return dir;
}

bool statistics_db::pathExists(std::string path)
{
    std::ifstream file;
    file.open(path, std::ios::in);
    if(file.is_open())
    {
        file.close();
        return true;
    }

    else
    {
        return false;
    }
}