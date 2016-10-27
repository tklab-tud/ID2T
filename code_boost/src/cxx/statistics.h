/*
 * Class providing containers and access methods for statistical data collection.
 */
#ifndef CPP_PCAPREADER_STATISTICS_H
#define CPP_PCAPREADER_STATISTICS_H


#include <unordered_map>
#include <list>
#include <tuple>
#include <tins/timestamp.h>
#include <tins/ip_address.h>

/*
 * Definition of structs used in unordered_map fields
 */

/*
 * Struct used as data structure for method get_stats_for_ip, represents:
 * - Incoming bandwidth in KBits
 * - Outgoing bandwidth in KBits
 * - Number of incoming packets per second
 * - Number of outgoing packets per second
 * - Average size of sent packets in kbytes
 * - Average size of received packets in kybtes
 * - Average value of TCP option Maximum Segment Size (MSS)
 */
struct ip_stats {
    float bandwidthKBitsIn;
    float bandwidthKBitsOut;
    float packetPerSecondIn;
    float packetPerSecondOut;
    float AvgPacketSizeSent;
    float AvgPacketSizeRecv;
    long AvgMaxSegmentSizeTCP;
};

/*
 * Struct used to represent:
 * - IP address (IPv4 or IPv6)
 * - TTL value
 */
struct ipAddress_ttl {
    std::string ipAddress;
    int ttlValue;

    bool operator==(const ipAddress_ttl &other) const {
        return ipAddress == other.ipAddress
               && ttlValue == other.ttlValue;
    }
};

/*
 * Struct used to represent:
 * - IP address (IPv4 or IPv6)
 * - Protocol (e.g. TCP, UDP, IPv4, IPv6)
 */
struct ipAddress_protocol {
    std::string ipAddress;
    std::string protocol;

    bool operator==(const ipAddress_protocol &other) const {
        return ipAddress == other.ipAddress
               && protocol == other.protocol;
    }
};

/*
 * Struct used to represent:
 * - Number of received packets
 * - Number of sent packets
 * - Data received in kbytes
 * - Data sent in kbytes
 */
struct entry_ipStat {
    long pkts_received;
    long pkts_sent;
    float kbytes_received;
    float kbytes_sent;

    bool operator==(const entry_ipStat &other) const {
        return pkts_received == other.pkts_received
               && pkts_sent == other.pkts_sent
               && kbytes_sent == other.kbytes_sent
               && kbytes_received == other.kbytes_received;
    }
};

/*
 * Struct used to represent:
 * - IP address (IPv4 or IPv6)
   - Traffic direction (out: outgoing connection, in: incoming connection)
 * - Port number
 */
struct ipAddress_inOut_port {
    std::string ipAddress;
    std::string trafficDirection;
    int portNumber;

    bool operator==(const ipAddress_inOut_port &other) const {
        return ipAddress == other.ipAddress
               && trafficDirection == other.trafficDirection
               && portNumber == other.portNumber;
    }

};

/*
 * Definition of hash functions for structs used as key in unordered_map
 */
namespace std {
    template<>
    struct hash<ipAddress_ttl> {
        std::size_t operator()(const ipAddress_ttl &k) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(k.ipAddress)
                     ^ (hash<int>()(k.ttlValue) << 1)) >> 1);
        }
    };

    template<>
    struct hash<ipAddress_protocol> {
        std::size_t operator()(const ipAddress_protocol &k) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(k.ipAddress)
                     ^ (hash<string>()(k.protocol) << 1)) >> 1);
        }
    };

    template<>
    struct hash<ipAddress_inOut_port> {
        std::size_t operator()(const ipAddress_inOut_port &k) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(k.ipAddress)
                     ^ (hash<string>()(k.trafficDirection) << 1)) >> 1)
                   ^ (hash<int>()(k.portNumber) << 1);
        }
    };
}

class statistics {
public:
    /*
     * Constructor
     */
    statistics();

    /*
     * Methods
     */
    std::string getFormattedTimestamp(time_t seconds, suseconds_t microseconds) const;

    /*
    * Access methods for containers
    */
    void incrementPacketCount();

    void incrementTTLcount(std::string ipAddress, int ttlValue);

    void incrementProtocolCount(std::string ipAddress, std::string protocol);

    void incrementPortCount(std::string ipAddressSender, int outgoingPort, std::string ipAddressReceiver,
                            int incomingPort);

    int getProtocolCount(std::string ipAddress, std::string protocol);

    void setTimestampFirstPacket(Tins::Timestamp ts);

    void setTimestampLastPacket(Tins::Timestamp ts);

    void assign_mac_address(std::string ipAddress, std::string macAddress);

    void addIpStat_packetSent(std::string ipAddressSender, std::string ipAddressReceiver, long bytesSent);

    void addMSS(std::string ipAddress, int MSSvalue);

    void writeToDatabase(std::string database_path);

    void addPacketSize(uint32_t packetSize);

    std::string getCaptureDurationTimestamp() const;

    float getCaptureDurationSeconds() const;

    float getAvgPacketSize() const;

    void printStats(std::string ipAddress);

    /*
     * IP Address-specific statistics
     */
    ip_stats getStatsForIP(std::string ipAddress);


private:
    /*
     * Data fields
     */
    Tins::Timestamp timestamp_firstPacket;
    Tins::Timestamp timestamp_lastPacket;
    float sumPacketSize = 0;
    int packetCount = 0;

    /*
     * Data containers
     */
    // {IP Address, TTL value, count}
    std::unordered_map<ipAddress_ttl, int> ttl_distribution;

    // {IP Address, Protocol, count}
    std::unordered_map<ipAddress_protocol, int> protocol_distribution;

    // {IP Address,  #received packets, #sent packets, Data received in kbytes, Data sent in kbytes}
    std::unordered_map<std::string, entry_ipStat> ip_statistics;

    // {IP Address, in_out, Port Number, count}
    std::unordered_map<ipAddress_inOut_port, int> ip_ports;

    // {IP Address, MAC Address}
    std::unordered_map<std::string, std::string> ip_mac_mapping;

    // {IP Address, avg MSS}
    std::unordered_map<std::string, int> ip_sumMss;
};


#endif //CPP_PCAPREADER_STATISTICS_H
