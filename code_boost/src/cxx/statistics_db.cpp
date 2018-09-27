#include "statistics_db.h"
#include <math.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include <stdio.h>
#include <pybind11/pybind11.h>
namespace py = pybind11;

/**
 * Creates a new statistics_db object. Opens an existing database located at database_path. If not existing, creates
 * a new database at database_path.
 * @param database_path The file path of the database.
 */
statistics_db::statistics_db(std::string database_path, std::string resourcePath) {
    // Append file extension if not present
    if (database_path.find(".sqlite3") == database_path.npos) {
        database_path += ".sqlite3";
    }
    // creates the DB if not existing, opens the DB for read+write access
    db.reset(new SQLite::Database(database_path, SQLite::OPEN_CREATE | SQLite::OPEN_READWRITE));

    this->resourcePath = resourcePath;

    // Read ports and services into portServices vector
    readPortServicesFromNmap();
}

void statistics_db::getNoneExtraTestsInveralStats(std::vector<double>& intervals){
    try {
        //SQLite::Statement query(*db, "SELECT name FROM sqlite_master WHERE type='table' AND name='interval_tables';");
        std::vector<std::string> tables;
        try {
            SQLite::Statement query(*db, "SELECT name FROM interval_tables WHERE extra_tests=1;");
            while (query.executeStep()) {
                tables.push_back(query.getColumn(0));
            }
        } catch (std::exception &e) {
            std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
        }
        if (tables.size() != 0) {
            std::string table_name;
            double interval;
            for (auto table = tables.begin(); table != tables.end(); table++) {
                table_name = table->substr(std::string("interval_statistics_").length());
                interval = static_cast<double>(::atof(table_name.c_str()))/1000000;
                auto found = std::find(intervals.begin(), intervals.end(), interval);
                if (found != intervals.end()) {
                    intervals.erase(found, found);
                }
            }
        }
    } catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the IP statistics into the database.
 * @param ipStatistics The IP statistics from class statistics.
 */
void statistics_db::writeStatisticsIP(const std::unordered_map<std::string, entry_ipStat> &ipStatistics) {
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
            const entry_ipStat &e = it->second;
            query.bindNoCopy(1, it->first);
            query.bind(2, (int) e.pkts_received);
            query.bind(3, (int) e.pkts_sent);
            query.bind(4, e.kbytes_received);
            query.bind(5, e.kbytes_sent);
            query.bind(6, e.max_interval_pkt_rate);
            query.bind(7, e.min_interval_pkt_rate);
            query.bindNoCopy(8, e.ip_class);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the IP Degrees into the database.
 * @param ipStatistics The IP statistics from class statistics. Degree Statistics are supposed to be integrated into the ip_statistics table later on,
 *        therefore they use the same parameter. But for now they are inserted into their own table.
 */
void statistics_db::writeStatisticsDegree(const std::unordered_map<std::string, entry_ipStat> &ipStatistics){
    try {
        db->exec("DROP TABLE IF EXISTS ip_degrees");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_degrees ( "
                "ipAddress TEXT, "
                "inDegree INTEGER, "
                "outDegree INTEGER, "
                "overallDegree INTEGER, "
                "PRIMARY KEY(ipAddress));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_degrees VALUES (?, ?, ?, ?)");
        for (auto it = ipStatistics.begin(); it != ipStatistics.end(); ++it) {
            const entry_ipStat &e = it->second;
            query.bindNoCopy(1, it->first);
            query.bind(2, e.in_degree);
            query.bind(3, e.out_degree);
            query.bind(4, e.overall_degree);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the TTL distribution into the database.
 * @param ttlDistribution The TTL distribution from class statistics.
 */
void statistics_db::writeStatisticsTTL(const std::unordered_map<ipAddress_ttl, int> &ttlDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS ip_ttl");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE ip_ttl ("
                "ipAddress TEXT,"
                "ttlValue INTEGER,"
                "ttlCount INTEGER,"
                "PRIMARY KEY(ipAddress,ttlValue));"
                "CREATE INDEX ipAddressTTL ON ip_ttl(ipAddress);";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_ttl VALUES (?, ?, ?)");
        for (auto it = ttlDistribution.begin(); it != ttlDistribution.end(); ++it) {
            const ipAddress_ttl &e = it->first;
            query.bindNoCopy(1, e.ipAddress);
            query.bind(2, e.ttlValue);
            query.bind(3, it->second);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the MSS distribution into the database.
 * @param mssDistribution The MSS distribution from class statistics.
 */
void statistics_db::writeStatisticsMSS(const std::unordered_map<ipAddress_mss, int> &mssDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS tcp_mss");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE tcp_mss ("
                "ipAddress TEXT,"
                "mssValue INTEGER,"
                "mssCount INTEGER,"
                "PRIMARY KEY(ipAddress,mssValue));"
                "CREATE INDEX ipAddressMSS ON tcp_mss(ipAddress);";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO tcp_mss VALUES (?, ?, ?)");
        for (auto it = mssDistribution.begin(); it != mssDistribution.end(); ++it) {
            const ipAddress_mss &e = it->first;
            query.bindNoCopy(1, e.ipAddress);
            query.bind(2, e.mssValue);
            query.bind(3, it->second);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the ToS distribution into the database.
 * @param tosDistribution The ToS distribution from class statistics.
 */
void statistics_db::writeStatisticsToS(const std::unordered_map<ipAddress_tos, int> &tosDistribution) {
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
            const ipAddress_tos &e = it->first;
            query.bindNoCopy(1, e.ipAddress);
            query.bind(2, e.tosValue);
            query.bind(3, it->second);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the window size distribution into the database.
 * @param winDistribution The window size distribution from class statistics.
 */
void statistics_db::writeStatisticsWin(const std::unordered_map<ipAddress_win, int> &winDistribution) {
    try {
        db->exec("DROP TABLE IF EXISTS tcp_win");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE tcp_win ("
                "ipAddress TEXT,"
                "winSize INTEGER,"
                "winCount INTEGER,"
                "PRIMARY KEY(ipAddress,winSize));"
                "CREATE INDEX ipAddressWIN ON tcp_win(ipAddress);";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO tcp_win VALUES (?, ?, ?)");
        for (auto it = winDistribution.begin(); it != winDistribution.end(); ++it) {
            const ipAddress_win &e = it->first;
            query.bindNoCopy(1, e.ipAddress);
            query.bind(2, e.winSize);
            query.bind(3, it->second);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the protocol distribution into the database.
 * @param protocolDistribution The protocol distribution from class statistics.
 */
void statistics_db::writeStatisticsProtocols(const std::unordered_map<ipAddress_protocol, entry_protocolStat> &protocolDistribution) {
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
            const ipAddress_protocol &e = it->first;
            query.bindNoCopy(1, e.ipAddress);
            query.bindNoCopy(2, e.protocol);
            query.bind(3, it->second.count);
            query.bind(4, it->second.byteCount);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the port statistics into the database.
 * @param portsStatistics The ports statistics from class statistics.
 */
void statistics_db::writeStatisticsPorts(const std::unordered_map<ipAddress_inOut_port, entry_portStat> &portsStatistics) {
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
                "PRIMARY KEY(ipAddress,portDirection,portNumber,portProtocol));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO ip_ports VALUES (?, ?, ?, ?, ?, ?, ?)");
        for (auto it = portsStatistics.begin(); it != portsStatistics.end(); ++it) {
            const ipAddress_inOut_port &e = it->first;

            std::string portService = portServices[e.portNumber];
            if(portService.empty()) {
                if(portServices[{0}] == "unavailable") {portService = "unavailable";}
                else {portService = "unknown";}
            }

            query.bindNoCopy(1, e.ipAddress);
            query.bindNoCopy(2, e.trafficDirection);
            query.bind(3, e.portNumber);
            query.bind(4, it->second.count);
            query.bind(5, it->second.byteCount);
            query.bindNoCopy(6, e.protocol);
            query.bindNoCopy(7, portService);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 *  Writes the IP address -> MAC address mapping into the database.
 * @param IpMacStatistics The IP address -> MAC address mapping from class statistics.
 */
void statistics_db::writeStatisticsIpMac(const std::unordered_map<std::string, std::string> &IpMacStatistics) {
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
            query.bindNoCopy(1, it->first);
            query.bindNoCopy(2, it->second);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
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
                                        float avgPacketsSentPerHost, float avgBandwidthIn, float avgBandwidthOut,
                                        bool doExtraTests) {
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
                "avgBandwidthOut REAL,"
                "doExtraTests INTEGER);";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO file_statistics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        query.bind(1, packetCount);
        query.bind(2, captureDuration);
        query.bind(3, timestampFirstPkt);
        query.bind(4, timestampLastPkt);
        query.bind(5, avgPacketRate);
        query.bind(6, avgPacketSize);
        query.bind(7, avgPacketsSentPerHost);
        query.bind(8, avgBandwidthIn);
        query.bind(9, avgBandwidthOut);
        query.bind(10, doExtraTests);
        query.exec();
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}


/**
 * Writes the conversation statistics into the database.
 * @param convStatistics The conversation from class statistics.
 */
void statistics_db::writeStatisticsConv(std::unordered_map<conv, entry_convStat> &convStatistics){
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
            const conv &f = it->first;
            entry_convStat &e = it->second;
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

                query.bindNoCopy(1, f.ipAddressA);
                query.bind(2, f.portA);
                query.bindNoCopy(3, f.ipAddressB);
                query.bind(4, f.portB);
                query.bind(5, (int) e.pkts_count);
                query.bind(6, (float) e.avg_pkt_rate);
                query.bind(7, (int) e.avg_interarrival_time.count());
                query.bind(8, minDelay);
                query.bind(9, maxDelay);
                query.exec();
                query.reset();

                if (PyErr_CheckSignals()) throw py::error_already_set();
            }
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the extended statistics for every conversation into the database.
 * @param conv_statistics_extended The extended conversation statistics from class statistics.
 */
void statistics_db::writeStatisticsConvExt(std::unordered_map<convWithProt, entry_convStatExt> &conv_statistics_extended){
    try {
        db->exec("DROP TABLE IF EXISTS conv_statistics_extended");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE conv_statistics_extended ("
                "ipAddressA TEXT,"
                "portA INTEGER,"
                "ipAddressB TEXT,"
                "portB INTEGER,"
                "protocol TEXT COLLATE NOCASE,"
                "pktsCount INTEGER,"
                "avgPktRate REAL,"
                "avgDelay INTEGER,"
                "minDelay INTEGER,"
                "maxDelay INTEGER,"
                "avgIntervalPktCount REAL,"
                "avgTimeBetweenIntervals REAL,"
                "avgIntervalTime REAL,"
                "totalConversationDuration REAL,"
                "PRIMARY KEY(ipAddressA,portA,ipAddressB,portB,protocol));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO conv_statistics_extended VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        // iterate over every conversation and interval aggregation pair and store the respective values in the database
        for (auto it = conv_statistics_extended.begin(); it != conv_statistics_extended.end(); ++it) {
            const convWithProt &f = it->first;
            entry_convStatExt &e = it->second;

            int sumDelay = 0;
            int minDelay = -1;
            int maxDelay = -1;

            if (e.pkts_count > 1 && f.protocol == "TCP"){
                for (int i = 0; (unsigned) i < e.interarrival_time.size(); i++) {
                    sumDelay += e.interarrival_time[i].count();
                    if (maxDelay < e.interarrival_time[i].count())
                        maxDelay = e.interarrival_time[i].count();
                    if (minDelay > e.interarrival_time[i].count() || minDelay == -1)
                        minDelay = e.interarrival_time[i].count();
                }
                if (e.interarrival_time.size() > 0)
                    e.avg_interarrival_time = (std::chrono::microseconds) sumDelay / e.interarrival_time.size(); // average
                else
                    e.avg_interarrival_time = (std::chrono::microseconds) 0;
            }

            if (e.total_comm_duration == 0)
                e.avg_pkt_rate = e.pkts_count; // pkt per sec
            else
                e.avg_pkt_rate = e.pkts_count / e.total_comm_duration;

            if (e.avg_int_pkts_count > 0){
                query.bindNoCopy(1, f.ipAddressA);
                query.bind(2, f.portA);
                query.bindNoCopy(3, f.ipAddressB);
                query.bind(4, f.portB);
                query.bindNoCopy(5, f.protocol);
                query.bind(6, (int) e.pkts_count);
                query.bind(7, (float) e.avg_pkt_rate);

                if (f.protocol == "UDP" || (f.protocol == "TCP" && e.pkts_count < 2))
                    query.bind(8);
                else
                    query.bind(8, (int) e.avg_interarrival_time.count());

                if (minDelay == -1)
                    query.bind(9);
                else
                    query.bind(9, minDelay);

                if (maxDelay == -1)
                    query.bind(10);
                else
                    query.bind(10, maxDelay);

                query.bind(11, e.avg_int_pkts_count);
                query.bind(12, e.avg_time_between_ints);
                query.bind(13, e.avg_interval_time);
                query.bind(14, e.total_comm_duration);
                query.exec();
                query.reset();

                if (PyErr_CheckSignals()) throw py::error_already_set();
            }

        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}

/**
 * Writes the interval statistics into the database.
 * @param intervalStatistics The interval entries from class statistics.
 */
void statistics_db::writeStatisticsInterval(const std::unordered_map<std::string, entry_intervalStat> &intervalStatistics, std::vector<std::chrono::duration<int, std::micro>> timeIntervals, bool del, int defaultInterval, bool extraTests){
    try {
        // remove old tables produced by prior database versions
        db->exec("DROP TABLE IF EXISTS interval_statistics");

        // delete all former interval statistics, if requested
        if (del) {
            SQLite::Statement query(*db, "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'interval_statistics_%';");
            std::vector<std::string> previous_tables;
            while (query.executeStep()) {
                previous_tables.push_back(query.getColumn(0));
            }
            for (std::string table: previous_tables) {
                db->exec("DROP TABLE IF EXISTS " + table);
            }
            db->exec("DROP TABLE IF EXISTS interval_tables");
        }

        // create interval table index
        db->exec("CREATE TABLE IF NOT EXISTS interval_tables (name TEXT, is_default INTEGER, extra_tests INTEGER);");

        std::string default_table_name = "";
        // get name for default table
        try {
            SQLite::Statement query(*db, "SELECT name FROM interval_tables WHERE is_default=1;");
            query.executeStep();
            default_table_name = query.getColumn(0).getString();

        } catch (std::exception &e) {
            std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
        }

        // handle default interval only runs
        std::string is_default = "0";
        std::chrono::duration<int, std::micro> defaultTimeInterval(defaultInterval);
        if (defaultInterval != 0.0) {
            is_default = "1";
            if (timeIntervals.empty() || timeIntervals[0].count() == 0) {
                timeIntervals.clear();
                timeIntervals.push_back(defaultTimeInterval);
            }
        }

        // extra tests handling
        std::string extra = "0";
        if (extraTests) {
            extra = "1";
        }

        for (auto timeInterval: timeIntervals) {
            // get interval statistics table name
            std::ostringstream strs;
            strs << timeInterval.count();
            std::string table_name = "interval_statistics_" + strs.str();

            // check for recalculation of default table
            if (table_name == default_table_name || timeInterval == defaultTimeInterval) {
                is_default = "1";
            } else {
                is_default = "0";
            }

            // add interval_tables entry
            db->exec("DELETE FROM interval_tables WHERE name = '" + table_name + "';");
            db->exec("INSERT INTO interval_tables VALUES ('" + table_name + "', '" + is_default + "', '" + extra + "');");

            // new interval statistics implementation
            db->exec("DROP TABLE IF EXISTS " + table_name);
            SQLite::Transaction transaction(*db);
            db->exec("CREATE TABLE " + table_name + " ("
                    "lastPktTimestamp TEXT,"
                    "startTimestamp TEXT,"
                    "endTimestamp TEXT,"
                    "pktsCount INTEGER,"
                    "pktRate REAL,"
                    "kBytes REAL,"
                    "kByteRate REAL,"
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
                    "PortEntropy REAL,"
                    "TTLEntropy REAL,"
                    "WinSizeEntropy REAL,"
                    "ToSEntropy REAL,"
                    "MSSEntropy REAL,"
                    "newPortEntropy REAL,"
                    "newTTLEntropy REAL,"
                    "newWinSizeEntropy REAL,"
                    "newToSEntropy REAL,"
                    "newMSSEntropy REAL,"
                    "PortEntropyNormalized REAL,"
                    "TTLEntropyNormalized REAL,"
                    "WinSizeEntropyNormalized REAL,"
                    "ToSEntropyNormalized REAL,"
                    "MSSEntropyNormalized REAL,"
                    "newPortEntropyNormalized REAL,"
                    "newTTLEntropyNormalized REAL,"
                    "newWinSizeEntropyNormalized REAL,"
                    "newToSEntropyNormalized REAL,"
                    "newMSSEntropyNormalized REAL,"
                    "PRIMARY KEY(lastPktTimestamp));");

            double ttl_entropy = 0.0;
            double win_size_entropy = 0.0;
            double tos_entropy = 0.0;
            double mss_entropy = 0.0;
            double port_entropy = 0.0;
            double ttl_novel_entropy = 0.0;
            double win_size_novel_entropy = 0.0;
            double tos_novel_entropy = 0.0;
            double mss_novel_entropy = 0.0;
            double port_novel_entropy = 0.0;
            for (auto it = intervalStatistics.begin(); it != intervalStatistics.end(); ++it) {
                const entry_intervalStat &e = it->second;
                if (ttl_entropy < e.ttl_entropies[0]) {
                    ttl_entropy = e.ttl_entropies[0];
                }
                if (win_size_entropy < e.win_size_entropies[0]) {
                    win_size_entropy = e.win_size_entropies[0];
                }
                if (tos_entropy < e.tos_entropies[0]) {
                    tos_entropy = e.tos_entropies[0];
                }
                if (mss_entropy < e.mss_entropies[0]) {
                    mss_entropy = e.mss_entropies[0];
                }
                if (port_entropy < e.port_entropies[0]) {
                    port_entropy = e.port_entropies[0];
                }
                if (ttl_novel_entropy < e.ttl_entropies[1]) {
                    ttl_novel_entropy = e.ttl_entropies[1];
                }
                if (win_size_novel_entropy < e.win_size_entropies[1]) {
                    win_size_novel_entropy = e.win_size_entropies[1];
                }
                if (tos_novel_entropy < e.tos_entropies[1]) {
                    tos_novel_entropy = e.tos_entropies[1];
                }
                if (mss_novel_entropy < e.mss_entropies[1]) {
                    mss_novel_entropy = e.mss_entropies[1];
                }
                if (port_novel_entropy < e.port_entropies[1]) {
                    port_novel_entropy = e.port_entropies[1];
                }
            }

            SQLite::Statement query(*db, "INSERT INTO " + table_name + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            for (auto it = intervalStatistics.begin(); it != intervalStatistics.end(); ++it) {
                const entry_intervalStat &e = it->second;

                query.bindNoCopy(1, it->first);
                query.bind(2, e.start);
                query.bind(3, e.end);
                query.bind(4, (int)e.pkts_count);
                query.bind(5, e.pkt_rate);
                query.bind(6, e.kbytes);
                query.bind(7, e.kbyte_rate);
                query.bind(8, e.ip_src_entropy);
                query.bind(9, e.ip_dst_entropy);
                query.bind(10, e.ip_src_cum_entropy);
                query.bind(11, e.ip_dst_cum_entropy);
                query.bind(12, e.payload_count);
                query.bind(13, e.incorrect_tcp_checksum_count);
                query.bind(14, e.correct_tcp_checksum_count);
                query.bind(15, e.novel_ip_count);
                query.bind(16, e.novel_port_count);
                query.bind(17, e.novel_ttl_count);
                query.bind(18, e.novel_win_size_count);
                query.bind(19, e.novel_tos_count);
                query.bind(20, e.novel_mss_count);
                query.bind(21, e.port_entropies[0]);
                query.bind(22, e.ttl_entropies[0]);
                query.bind(23, e.win_size_entropies[0]);
                query.bind(24, e.tos_entropies[0]);
                query.bind(25, e.mss_entropies[0]);
                query.bind(26, e.port_entropies[1]);
                query.bind(27, e.ttl_entropies[1]);
                query.bind(28, e.win_size_entropies[1]);
                query.bind(29, e.tos_entropies[1]);
                query.bind(30, e.mss_entropies[1]);
                query.bind(31, e.port_entropies[0]/port_entropy);
                query.bind(32, e.ttl_entropies[0]/ttl_entropy);
                query.bind(33, e.win_size_entropies[0]/win_size_entropy);
                query.bind(34, e.tos_entropies[0]/tos_entropy);
                query.bind(35, e.mss_entropies[0]/mss_entropy);
                query.bind(36, e.port_entropies[1]/port_novel_entropy);
                query.bind(37, e.ttl_entropies[1]/ttl_novel_entropy);
                query.bind(38, e.win_size_entropies[1]/win_size_novel_entropy);
                query.bind(39, e.tos_entropies[1]/tos_novel_entropy);
                query.bind(40, e.mss_entropies[1]/mss_novel_entropy);
                query.exec();
                query.reset();

                if (PyErr_CheckSignals()) throw py::error_already_set();
            }
            transaction.commit();
        }
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
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
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
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
    std::string nmapPath = resourcePath + "nmap-services-tcp.csv";
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
        portServices.insert({0, "unavailable"});
    }
}

/**
 * Writes the unrecognized PDUs into the database.
 * @param unrecognized_PDUs The unrecognized PDUs from class statistics.
 */
void statistics_db::writeStatisticsUnrecognizedPDUs(const std::unordered_map<unrecognized_PDU, unrecognized_PDU_stat>
                                                    &unrecognized_PDUs) {
    try {
        db->exec("DROP TABLE IF EXISTS unrecognized_pdus");
        SQLite::Transaction transaction(*db);
        const char *createTable = "CREATE TABLE unrecognized_pdus ("
                "srcMac TEXT COLLATE NOCASE,"
                "dstMac TEXT COLLATE NOCASE,"
                "etherType INTEGER,"
                "pktCount INTEGER,"
                "timestampLastOccurrence TEXT,"
                "PRIMARY KEY(srcMac,dstMac,etherType));";
        db->exec(createTable);
        SQLite::Statement query(*db, "INSERT INTO unrecognized_pdus VALUES (?, ?, ?, ?, ?)");
        for (auto it = unrecognized_PDUs.begin(); it != unrecognized_PDUs.end(); ++it) {
            const unrecognized_PDU &e = it->first;
            query.bindNoCopy(1, e.srcMacAddress);
            query.bindNoCopy(2, e.dstMacAddress);
            query.bind(3, e.typeNumber);
            query.bind(4, it->second.count);
            query.bindNoCopy(5, it->second.timestamp_last_occurrence);
            query.exec();
            query.reset();

            if (PyErr_CheckSignals()) throw py::error_already_set();
        }
        transaction.commit();
    }
    catch (std::exception &e) {
        std::cerr << "Exception in statistics_db::" << __func__ << ": " << e.what() << std::endl;
    }
}
