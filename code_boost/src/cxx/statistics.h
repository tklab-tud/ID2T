/*
 * Class providing containers and access methods for statistical data collection.
 */
#ifndef CPP_PCAPREADER_STATISTICS_H
#define CPP_PCAPREADER_STATISTICS_H

// Aidmar
#include <vector>

#include <unordered_map>
#include <list>
#include <tuple>
#include <tins/timestamp.h>
#include <tins/ip_address.h>

#include "utilities.h"

using namespace Tins;

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


// Aidmar
/*
 * Struct used to represent a conv by:
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


// Aidmar
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

// Aidmar
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

// Aidmar
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
    // Aidmar
    std::string ip_class;
    std::vector<float> interval_pkt_rate;
    float max_pkt_rate;
    float min_pkt_rate;
    // Aidmar - to calculate Mahoney anomaly score
    long firstAppearAsSenderPktCount;
    long firstAppearAsReceiverPktCount;
    float sourceAnomalyScore;
    float destinationAnomalyScore;
    // Aidmar- To collect statstics over time interval
    std::vector<std::chrono::microseconds> pktsSentTimestamp;
    std::vector<std::chrono::microseconds> pktsReceivedTimestamp;

    bool operator==(const entry_ipStat &other) const {
        return pkts_received == other.pkts_received
               && pkts_sent == other.pkts_sent
               && kbytes_sent == other.kbytes_sent
               && kbytes_received == other.kbytes_received
                // Aidmar
               && interval_pkt_rate == other.interval_pkt_rate
               && max_pkt_rate == other.max_pkt_rate
               && min_pkt_rate == other.min_pkt_rate
               && ip_class == other.ip_class
               && firstAppearAsSenderPktCount == other.firstAppearAsSenderPktCount
               && firstAppearAsReceiverPktCount == other.firstAppearAsReceiverPktCount
               && sourceAnomalyScore == other.sourceAnomalyScore
               && destinationAnomalyScore == other.destinationAnomalyScore
               && pktsSentTimestamp == other.pktsSentTimestamp
               && pktsReceivedTimestamp == other.pktsReceivedTimestamp;
    }
};

// Aidmar
/*
 * Struct used to represent interval statistics:
 * - Number of packets
 * - IP source entropy
 * - IP destination entropy
 * - IP source cumulative entropy
 * - IP destination cumulative entropy
 */
struct entry_intervalStat {
    int pkts_count;
    float kbytes;
    float ip_src_entropy; 
    float ip_dst_entropy;
    float ip_src_cum_entropy; 
    float ip_dst_cum_entropy;
    int payload_count;
    int incorrect_checksum_count;
    int correct_checksum_count;
    int invalid_tos_count;
    int valid_tos_count;
    int new_ip_count;
    int new_ttl_count;
    int new_win_size_count;
    int new_tos_count;
    int new_mss_count;

    bool operator==(const entry_intervalStat &other) const {
        return pkts_count == other.pkts_count
               && kbytes == other.kbytes
               && ip_src_entropy == other.ip_src_entropy
               && ip_dst_entropy == other.ip_dst_entropy
               && ip_src_cum_entropy == other.ip_src_cum_entropy
               && ip_dst_cum_entropy == other.ip_dst_cum_entropy
               && payload_count == other.payload_count
               && incorrect_checksum_count == other.incorrect_checksum_count
               && invalid_tos_count == other.invalid_tos_count
               && valid_tos_count == other.valid_tos_count
               && new_ip_count == other.new_ip_count
               && new_ttl_count == other.new_ttl_count
               && new_win_size_count == other.new_win_size_count
               && new_tos_count == other.new_tos_count
               && new_mss_count == other.new_mss_count;
    }
};

// Aidmar
/*
 * Struct used to represent:
 * - Number of packets from A to B
 * - Number of packets from B to A
 */
struct entry_convStat {
    long pkts_count;
    float avg_pkt_rate;
    std::vector<std::chrono::microseconds> pkts_timestamp;
    std::vector<std::chrono::microseconds> pkts_delay;
    std::chrono::microseconds avg_delay;
    std::chrono::microseconds standardDeviation_delay;
    
    bool operator==(const entry_convStat &other) const {
        return pkts_count == other.pkts_count
               && avg_pkt_rate == avg_pkt_rate
               && pkts_timestamp == other.pkts_timestamp
               && pkts_delay == other.pkts_delay
               && avg_delay == other.avg_delay
               && standardDeviation_delay == other.standardDeviation_delay;
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

    // Aidmar
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

    // Aidmar
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

    // Aidmar
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
    
    // Aidmar: TO-DO:??
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

    // Adimar
    void calculateIPIntervalPacketRate(std::chrono::duration<int, std::micro> interval, std::chrono::microseconds intervalStartTimestamp);
    void incrementMSScount(std::string ipAddress, int mssValue);
    void incrementWinCount(std::string ipAddress, int winSize);   
    void addConvStat(std::string ipAddressSender,int sport,std::string ipAddressReceiver,int dport, std::chrono::microseconds timestamp);
    std::vector<float> calculateIPsCumEntropy();
    std::vector<float> calculateLastIntervalIPsEntropy(std::chrono::microseconds intervalStartTimestamp);        
    void addIntervalStat(std::chrono::duration<int, std::micro> interval, std::chrono::microseconds intervalStartTimestamp, std::chrono::microseconds lastPktTimestamp);
    void checkPayload(const PDU *pdu_l4);
    void checkTCPChecksum(std::string ipAddressSender, std::string ipAddressReceiver, TCP tcpPkt);
    void checkToS(uint8_t ToS);
    void incrementToScount(std::string ipAddress, int tosValue);

    void incrementTTLcount(std::string ipAddress, int ttlValue);

    void incrementProtocolCount(std::string ipAddress, std::string protocol);

    void incrementPortCount(std::string ipAddressSender, int outgoingPort, std::string ipAddressReceiver,
                            int incomingPort);

    int getProtocolCount(std::string ipAddress, std::string protocol);

    void setTimestampFirstPacket(Tins::Timestamp ts);

    void setTimestampLastPacket(Tins::Timestamp ts);
    
    // Aidmar
    Tins::Timestamp getTimestampFirstPacket();
    Tins::Timestamp getTimestampLastPacket();

    void assignMacAddress(std::string ipAddress, std::string macAddress);
    
    // Aidmar
    void addIpStat_packetSent(std::string filePath, std::string ipAddressSender, std::string ipAddressReceiver, long bytesSent, std::chrono::microseconds timestamp);
    int getPacketCount();
    int getSumPacketSize();

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

    // Aidmar
    bool getDoExtraTests();
    void setDoExtraTests(bool var);

private:
    /*
     * Data fields
     */
    Tins::Timestamp timestamp_firstPacket;
    Tins::Timestamp timestamp_lastPacket;
    float sumPacketSize = 0;
    int packetCount = 0;

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

    // Variables that are used for interval-wise tests
    int intervalPayloadCount = 0;
    int intervalIncorrectTCPChecksumCount = 0;
    int intervalCorrectTCPChecksumCount = 0;
    int intervalCumPktCount = 0;
    float intervalCumSumPktSize = 0;
    int intervalCumNewIPCount = 0;
    int intervalCumNewTTLCount = 0;
    int intervalCumNewWinSizeCount = 0;
    int intervalCumNewToSCount = 0;
    int intervalCumNewMSSCount = 0;

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

    // {IP Address A, Port A, IP Address B, Port B,   #packets_A_B, #packets_B_A}
    std::unordered_map<conv, entry_convStat> conv_statistics;

    std::unordered_map<std::string, entry_intervalStat> interval_statistics;



    // {TTL value, count}
    std::unordered_map<int, int> ttl_values;

    // {Win size, count}
    std::unordered_map<int, int> win_values;

    // {ToS, count}
    std::unordered_map<int, int> tos_values;

    // {MSS, count}
    std::unordered_map<int, int> mss_values;

    // {IP Address, Protocol, count}
    std::unordered_map<ipAddress_protocol, int> protocol_distribution;

    // {IP Address,  #received packets, #sent packets, Data received in kbytes, Data sent in kbytes}
    std::unordered_map<std::string, entry_ipStat> ip_statistics;

    // {IP Address, in_out, Port Number, count}
    std::unordered_map<ipAddress_inOut_port, int> ip_ports;

    // {IP Address, MAC Address}
    std::unordered_map<std::string, std::string> ip_mac_mapping;

    // Aidmar
    // {DSCP value, count}
    std::unordered_map<int, int> dscp_distribution;
};


#endif //CPP_PCAPREADER_STATISTICS_H
