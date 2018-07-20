/*
 * Class providing containers and access methods for statistical data collection.
 */
#ifndef CPP_PCAPREADER_STATISTICS_H
#define CPP_PCAPREADER_STATISTICS_H

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <tuple>
#include <tins/timestamp.h>
#include <tins/ip_address.h>

#include "utilities.h"

using namespace Tins;

#define COMM_INTERVAL_THRESHOLD 10e6  // in microseconds; i.e. here 10s

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
};

/*
 * Struct used to represent a conversation by:
 * - IP address A
 * - Port A
 * - IP address B
 * - Port B
 */
struct conv{
    std::string ipAddressA;
    int portA;
    std::string ipAddressB;
    int portB;

    bool operator==(const conv &other) const {
        return ipAddressA == other.ipAddressA
               && portA == other.portA
               &&ipAddressB == other.ipAddressB
               && portB == other.portB;
    }    
};

/*
 * Struct used to represent a conversation by:
 * - IP address A
 * - Port A
 * - IP address B
 * - Port B
 * - Protocol
 */
struct convWithProt{
    std::string ipAddressA;
    int portA;
    std::string ipAddressB;
    int portB;
    std::string protocol;

    bool operator==(const convWithProt &other) const {
        return ipAddressA == other.ipAddressA
               && portA == other.portA
               &&ipAddressB == other.ipAddressB
               && portB == other.portB
               && protocol == other.protocol;
    }    
};

/*
 * Struct used to represent:
 * - IP address (IPv4 or IPv6)
 * - MSS value
 */
struct ipAddress_mss {
    std::string ipAddress;
    int mssValue;

    bool operator==(const ipAddress_mss &other) const {
        return ipAddress == other.ipAddress
               && mssValue == other.mssValue;
    }
};

/*
 * Struct used to represent:
 * - IP address (IPv4 or IPv6)
 * - ToS value
 */
struct ipAddress_tos {
    std::string ipAddress;
    int tosValue;

    bool operator==(const ipAddress_tos &other) const {
        return ipAddress == other.ipAddress
               && tosValue == other.tosValue;
    }
};

/*
 * Struct used to represent:
 * - IP address (IPv4 or IPv6)
 * - Window size
 */
struct ipAddress_win {
    std::string ipAddress;
    int winSize;

    bool operator==(const ipAddress_win &other) const {
        return ipAddress == other.ipAddress
               && winSize == other.winSize;
    }
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
    std::string ip_class;
    int in_degree;
    int out_degree;
    int overall_degree;
    // Collects statstics over time interval
    std::vector<float> interval_pkt_rate;
    float max_interval_pkt_rate;
    float min_interval_pkt_rate;
    std::vector<std::chrono::microseconds> pkts_sent_timestamp;
    std::vector<std::chrono::microseconds> pkts_received_timestamp;

    bool operator==(const entry_ipStat &other) const {
        return pkts_received == other.pkts_received
               && pkts_sent == other.pkts_sent
               && kbytes_sent == other.kbytes_sent
               && kbytes_received == other.kbytes_received
               && interval_pkt_rate == other.interval_pkt_rate
               && max_interval_pkt_rate == other.max_interval_pkt_rate
               && min_interval_pkt_rate == other.min_interval_pkt_rate
               && ip_class == other.ip_class
               && pkts_sent_timestamp == other.pkts_sent_timestamp
               && pkts_received_timestamp == other.pkts_received_timestamp;
    }
};
/*
 * Struct used to represent:
 * - Number of transmitted packets
 * - Number of transmitted bytes
 */
struct entry_portStat {
    int count;
    float byteCount;
};

/*
 * Struct used to represent:
 * - Number of times the protocol is seen
 * - Amount of bytes transmitted with this protocol
 */
struct entry_protocolStat {
    int count;
    float byteCount;
};

/*
 * Struct used to represent interval statistics:
 * - # packets
 * - # bytes
 * - IP source entropy
 * - IP destination entropy
 * - IP source cumulative entropy
 * - IP destination cumulative entropy
 * - # packets that have payload
 * - # incorrect TCP checksum
 * - # correct TCP checksum
 * - # novel IPs
 * - # novel TTL
 * - # novel Window Size
 * - # novel ToS
 * - # novel MSS
 */
struct entry_intervalStat {
    std::string start;
    std::string end;
    int pkts_count;
    float pkt_rate;
    float kbytes;
    float kbyte_rate;
    float ip_src_entropy; 
    float ip_dst_entropy;
    float ip_src_cum_entropy; 
    float ip_dst_cum_entropy;
    int payload_count;
    int incorrect_tcp_checksum_count;
    int correct_tcp_checksum_count;
    int novel_ip_count;
    int novel_ttl_count;
    int novel_win_size_count;
    int novel_tos_count;
    int novel_mss_count;
    int novel_port_count;

    bool operator==(const entry_intervalStat &other) const {
        return start == other.start
               && end == other.end
               && pkts_count == other.pkts_count
               && pkt_rate == other.pkt_rate
               && kbytes == other.kbytes
               && kbyte_rate == other.kbyte_rate
               && ip_src_entropy == other.ip_src_entropy
               && ip_dst_entropy == other.ip_dst_entropy
               && ip_src_cum_entropy == other.ip_src_cum_entropy
               && ip_dst_cum_entropy == other.ip_dst_cum_entropy
               && payload_count == other.payload_count
               && incorrect_tcp_checksum_count == other.incorrect_tcp_checksum_count
               && novel_ip_count == other.novel_ip_count
               && novel_ttl_count == other.novel_ttl_count
               && novel_win_size_count == other.novel_win_size_count
               && novel_tos_count == other.novel_tos_count
               && novel_mss_count == other.novel_mss_count
               && novel_port_count == other.novel_port_count;
    }
};

/*
 * Struct used to represent converstaion statistics:
 * - # packets
 * - Average packet rate
 * - Timestamps of packets
 * - Inter-arrival time
 * - Average inter-arrival time
 */
struct entry_convStat {
    long pkts_count;
    float avg_pkt_rate;
    std::vector<std::chrono::microseconds> pkts_timestamp;
    std::vector<std::chrono::microseconds> interarrival_time;
    std::chrono::microseconds avg_interarrival_time;

    bool operator==(const entry_convStat &other) const {
        return pkts_count == other.pkts_count
               && avg_pkt_rate == avg_pkt_rate
               && pkts_timestamp == other.pkts_timestamp
               && interarrival_time == other.interarrival_time
               && avg_interarrival_time == other.avg_interarrival_time;
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
    std::string protocol;

    bool operator==(const ipAddress_inOut_port &other) const {
        return ipAddress == other.ipAddress
               && trafficDirection == other.trafficDirection
               && portNumber == other.portNumber
               && protocol == other.protocol;
    }
};

/*
 * Struct used to represent a communication interval (for two hosts):
 * - Timestamp of the first packet in the interval
 * - Timestamp of the last packet in the interval
 * - The count of packets within the interval
 */
struct commInterval{
    std::chrono::microseconds start;
    std::chrono::microseconds end;
    long pkts_count;

    bool operator==(const commInterval &other) const {
        return start == other.start
               && end == other.end
               && pkts_count == other.pkts_count;
    }    
};

/*
 * Struct used to represent converstaion statistics:
 * - commnication intervals
 * - # packets
 * - Average packet rate
 * - average # packets per communication interval
 * - Average time between intervals
 * - Average duration of a communication interval
 * - Overall communication duration
 * - Timestamps of packets
 * - Inter-arrival time
 * - Average inter-arrival time
 */
struct entry_convStatExt {
    std::vector<commInterval> comm_intervals;
    long pkts_count;
    float avg_pkt_rate;
    double avg_int_pkts_count;
    double avg_time_between_ints;
    double avg_interval_time;
    double total_comm_duration;
    std::chrono::duration<int, std::micro> timeInterval;
    std::vector<std::chrono::microseconds> pkts_timestamp;
    std::vector<std::chrono::microseconds> interarrival_time;
    std::chrono::microseconds avg_interarrival_time;

    bool operator==(const entry_convStatExt &other) const {
        return comm_intervals == other.comm_intervals
               && pkts_count == other.pkts_count
               && avg_pkt_rate == avg_pkt_rate
               && avg_int_pkts_count == other.avg_int_pkts_count
               && avg_time_between_ints == other.avg_time_between_ints
               && avg_interval_time == other.avg_interval_time
               && total_comm_duration == other.total_comm_duration
               && pkts_timestamp == other.pkts_timestamp
               && interarrival_time == other.interarrival_time
               && avg_interarrival_time == other.avg_interarrival_time;
    }
};

/*
 * Struct used to represent:
 * - Source MAC address
 * - Destination MAC address
 * - Payload type number
 */
struct unrecognized_PDU {
    std::string srcMacAddress;
    std::string dstMacAddress;
    uint32_t typeNumber;

    bool operator==(const unrecognized_PDU &other) const {
        return srcMacAddress == other.srcMacAddress
               && dstMacAddress == other.dstMacAddress
               && typeNumber == other.typeNumber;
    }
};

/*
 * Struct used to represent:
 * - Number of occurrences
 * - Formatted timestamp of last occurrence
 */
struct unrecognized_PDU_stat {
    int count;
    std::string timestamp_last_occurrence;
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
    struct hash<ipAddress_mss> {
        std::size_t operator()(const ipAddress_mss &k) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(k.ipAddress)
                     ^ (hash<int>()(k.mssValue) << 1)) >> 1);
        }
    };

    template<>
    struct hash<ipAddress_tos> {
        std::size_t operator()(const ipAddress_tos &k) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(k.ipAddress)
                     ^ (hash<int>()(k.tosValue) << 1)) >> 1);
        }
    };

      template<>
    struct hash<ipAddress_win> {
        std::size_t operator()(const ipAddress_win &k) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(k.ipAddress)
                     ^ (hash<int>()(k.winSize) << 1)) >> 1);
        }
    };
    
    template<>
    struct hash<conv> {
        std::size_t operator()(const conv &k) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(k.ipAddressA)
                     ^ (hash<int>()(k.portA) << 1)) >> 1)
                     ^ ((hash<string>()(k.ipAddressB)
                     ^ (hash<int>()(k.portB) << 1)) >> 1);
        }
    };

    template<>
    struct hash<convWithProt> {
        std::size_t operator()(const convWithProt &c) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(c.ipAddressA)
                     ^ (hash<int>()(c.portA) << 1)) >> 1)
                     ^ ((hash<string>()(c.ipAddressB)
                     ^ (hash<int>()(c.portB) << 1)) >> 1)
                     ^ (hash<string>()(c.protocol));
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

    template<>
    struct hash<unrecognized_PDU> {
        std::size_t operator()(const unrecognized_PDU &k) const {
            using std::size_t;
            using std::hash;
            using std::string;
            return ((hash<string>()(k.srcMacAddress)
                     ^ (hash<string>()(k.dstMacAddress) << 1)) >> 1)
                   ^ (hash<uint32_t>()(k.typeNumber) << 1);
        }
    };
}

class statistics {
public:
    /*
     * Constructor
     */
    statistics(std::string resourcePath);

    /*
     * Methods
     */
    std::string getFormattedTimestamp(time_t seconds, suseconds_t microseconds) const;

    /*
    * Access methods for containers
    */
    void incrementPacketCount();

    void calculateIPIntervalPacketRate(std::chrono::duration<int, std::micro> interval, std::chrono::microseconds intervalStartTimestamp);

    void incrementMSScount(const std::string &ipAddress, int mssValue);

    void incrementWinCount(const std::string &ipAddress, int winSize);

    void addConvStat(const std::string &ipAddressSender,int sport, const std::string &ipAddressReceiver,int dport, std::chrono::microseconds timestamp);

    void addConvStatExt(const std::string &ipAddressSender,int sport, const std::string &ipAddressReceiver,int dport, const std::string &protocol, std::chrono::microseconds timestamp);

    void createCommIntervalStats();

    std::vector<float> calculateIPsCumEntropy();

    std::vector<float> calculateLastIntervalIPsEntropy(std::chrono::microseconds intervalStartTimestamp);

    void addIntervalStat(std::chrono::duration<int, std::micro> interval, std::chrono::microseconds intervalStartTimestamp, std::chrono::microseconds lastPktTimestamp);

    void checkPayload(const PDU *pdu_l4);

    void checkTCPChecksum(const std::string &ipAddressSender, const std::string &ipAddressReceiver, TCP tcpPkt);

    void checkToS(uint8_t ToS);

    void incrementToScount(const std::string &ipAddress, int tosValue);

    void incrementTTLcount(const std::string &ipAddress, int ttlValue);

    void incrementProtocolCount(const std::string &ipAddress, const std::string &protocol);

    void increaseProtocolByteCount(const std::string &ipAddress, const std::string &protocol, long bytesSent);

    void incrementUnrecognizedPDUCount(const std::string &srcMac, const std::string &dstMac, uint32_t typeNumber,
                                       const std::string &timestamp);

    void incrementPortCount(const std::string &ipAddressSender, int outgoingPort, const std::string &ipAddressReceiver,
                            int incomingPort, const std::string &protocol);

    void increasePortByteCount(const std::string &ipAddressSender, int outgoingPort, const std::string &ipAddressReceiver,
                               int incomingPort, long bytesSent, const std::string &protocol);

    int getProtocolCount(const std::string &ipAddress, const std::string &protocol);

    float getProtocolByteCount(const std::string &ipAddress, const std::string &protocol);

    void setTimestampFirstPacket(Tins::Timestamp ts);

    void setTimestampLastPacket(Tins::Timestamp ts);
    
    Tins::Timestamp getTimestampFirstPacket();
    Tins::Timestamp getTimestampLastPacket();

    void assignMacAddress(const std::string &ipAddress, const std::string &macAddress);
    
    void addIpStat_packetSent(const std::string &ipAddressSender, const std::string &ipAddressReceiver, long bytesSent, std::chrono::microseconds timestamp);

    int getPacketCount();

    int getSumPacketSize();

    void addMSS(const std::string &ipAddress, int MSSvalue);

    void writeToDatabase(std::string database_path, std::vector<std::chrono::duration<int, std::micro>> timeInterval, bool del);

    void addPacketSize(uint32_t packetSize);

    std::string getCaptureDurationTimestamp() const;

    float getCaptureDurationSeconds() const;

    float getAvgPacketSize() const;

    void printStats(const std::string &ipAddress);

    bool getDoExtraTests();

    void setDoExtraTests(bool var);

    int getDefaultInterval();

    void setDefaultInterval(int interval);

    /*
     * IP Address-specific statistics
     */
    ip_stats getStatsForIP(const std::string &ipAddress);

private:
    /*
     * Data fields
     */
    Tins::Timestamp timestamp_firstPacket;
    Tins::Timestamp timestamp_lastPacket;
    float sumPacketSize = 0;
    int packetCount = 0;
    std::string resourcePath;

    /* Extra tests includes:
     * - calculate IPs entropies for intervals
     * - calculate IPs cumulative entropies interval-wise
     * - check payload availability
     * - chech TCP checksum correctness
    */
    bool doExtraTests = false;

    int payloadCount = 0;
    int incorrectTCPChecksumCount = 0;
    int correctTCPChecksumCount = 0;

    // Variables that are used for interval-wise statistics
    int intervalPayloadCount = 0;
    int intervalIncorrectTCPChecksumCount = 0;
    int intervalCorrectTCPChecksumCount = 0;
    int intervalCumPktCount = 0;
    float intervalCumSumPktSize = 0;
    int intervalCumNovelIPCount = 0;
    int intervalCumNovelTTLCount = 0;
    int intervalCumNovelWinSizeCount = 0;
    int intervalCumNovelToSCount = 0;
    int intervalCumNovelMSSCount = 0;
    int intervalCumNovelPortCount = 0;

    int default_interval = 0;


    /*
     * Data containers
     */
    // {IP Address, TTL value, count}
    std::unordered_map<ipAddress_ttl, int> ttl_distribution;

    // {IP Address, MSS value, count}
    std::unordered_map<ipAddress_mss, int> mss_distribution;

    // {IP Address, Win size, count}
    std::unordered_map<ipAddress_win, int> win_distribution;

    // {IP Address, ToS value, count}
    std::unordered_map<ipAddress_tos, int> tos_distribution;

    // {IP Address A, Port A, IP Address B, Port B,   #packets, packets timestamps, inter-arrival times,
    // average of inter-arrival times}
    std::unordered_map<conv, entry_convStat> conv_statistics;

    // {IP Address A, Port A, IP Address B, Port B,   comm_intervals, #packets, avg. pkt rate, avg. #packets per interval,
    // avg. time between intervals, avg. interval time, duration, packets timestamps, inter-arrivtal times, average of inter-arrival times}
    // Also stores conversation with only one exchanged message. In this case avgPktRate, minDelay, maxDelay and avgDelay are -1
    std::unordered_map<convWithProt, entry_convStatExt> conv_statistics_extended;

    // {Last timestamp in the interval, #packets, #bytes, source IP entropy, destination IP entropy,
    // source IP cumulative entropy, destination IP cumulative entropy, #payload, #incorrect TCP checksum,
    // #correct TCP checksum, #novel IP, #novel TTL, #novel Window Size, #novel ToS,#novel MSS}
    std::unordered_map<std::string, entry_intervalStat> interval_statistics;

    // {TTL value, count}
    std::unordered_map<int, int> ttl_values;

    // {Win size, count}
    std::unordered_map<int, int> win_values;

    // {ToS, count}
    std::unordered_map<int, int> tos_values;

    // {MSS, count}
    std::unordered_map<int, int> mss_values;

    // {Port, count}
    std::unordered_map<int, int> port_values;


    //{IP Address, contacted IP Addresses}
    std::unordered_map<std::string, std::unordered_set<std::string>> contacted_ips;

    // {IP Address, Protocol,  #count, #Data transmitted in bytes}
    std::unordered_map<ipAddress_protocol, entry_protocolStat> protocol_distribution;

    // {IP Address,  #received packets, #sent packets, Data received in kbytes, Data sent in kbytes}
    std::unordered_map<std::string, entry_ipStat> ip_statistics;

    // {IP Address, in_out, Port Number,  #count, #Data transmitted in bytes}
    std::unordered_map<ipAddress_inOut_port, entry_portStat> ip_ports;

    // {IP Address, MAC Address}
    std::unordered_map<std::string, std::string> ip_mac_mapping;

    // {Source MAC, Destination MAC, typeNumber, #count, #timestamp of last occurrence}
    std::unordered_map<unrecognized_PDU, unrecognized_PDU_stat> unrecognized_PDUs;
};


#endif //CPP_PCAPREADER_STATISTICS_H
