// Aidmar
#include <iostream>
#include <fstream>
#include <vector>
#include <math.h> 

#include "statistics.h"
#include <sstream>
#include <SQLiteCpp/SQLiteCpp.h>
#include "statistics_db.h"

// Aidmar
void statistics::addIPEntropy(){
    std::vector <std::string> IPs; 
    std::vector <float> IPsSrcProb; 
    std::vector <float> IPsDstProb;
    for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
        IPs.push_back(i->first);        
        IPsSrcProb.push_back((float)i->second.pkts_sent/packetCount);
        IPsDstProb.push_back((float)i->second.pkts_received/packetCount);
        
        /*std::cout << i->first << ":" << i->second.pkts_sent << ":" << i->second.pkts_received << ":" 
        << i->second.firstAppearAsSenderPktCount << ":" << i->second.firstAppearAsReceiverPktCount << ":" 
        << packetCount << "\n";*/  
    }
    
    // Calculate IP source entropy 
    float IPsSrcEntropy = 0;
    for(unsigned i=0; i < IPsSrcProb.size();i++){
        if (IPsSrcProb[i] > 0)
            IPsSrcEntropy += - IPsSrcProb[i]*log2(IPsSrcProb[i]);
    }
    std::cout << packetCount << ": SrcEnt: " << IPsSrcEntropy << "\n";
    
    // Calculate IP destination entropy
    float IPsDstEntropy = 0;
    for(unsigned i=0; i < IPsDstProb.size();i++){
        if (IPsDstProb[i] > 0)
            IPsDstEntropy += - IPsDstProb[i]*log2(IPsDstProb[i]);
    }
    std::cout << packetCount << ": DstEnt: " << IPsDstEntropy << "\n";
    
    /*
    // Calculate IP source tn/r anomaly score
     float ipSrc_Mahoney_score = 0;
    // The number of IP sources (the different values)
    int s_r = 0;
    for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
            if (i->second.pkts_sent > 0)
                s_r++;
        }
    if(s_r > 0){
        // The number of the total instances
        int n = packetCount;
        // The packet count when the last novel IP was added as a sender
        int pktCntNvlSndr = 0;
        for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
            if (pktCntNvlSndr < i->second.firstAppearAsSenderPktCount)
                pktCntNvlSndr = i->second.firstAppearAsSenderPktCount;
        }
        // The "time" since last anomalous (novel) IP was appeared
        int s_t = packetCount - pktCntNvlSndr + 1;
        
        ipSrc_Mahoney_score = (float)s_t*n/s_r;
        
        std::cout << s_t << ":" << n << ":" << s_r << "\n";
        std::cout << packetCount << ": Mahoney score: " << ipSrc_Mahoney_score << "\n";
    }
    
    // Calculate IP destination tn/r anomaly score
    float ipDst_Mahoney_score = 0;
    // The number of IP sources (the different values)
    int d_r = 0;
    for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
            if (i->second.pkts_received > 0)
                d_r++;
        }
    if(d_r > 0){
        // The number of the total instances
        int n = packetCount;
        // The packet count when the last novel IP was added as a sender
        int pktCntNvlRcvr = 0;
        for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
            if (pktCntNvlRcvr < i->second.firstAppearAsReceiverPktCount)
                pktCntNvlRcvr = i->second.firstAppearAsReceiverPktCount;
        }
        // The "time" since last anomalous (novel) IP was appeared
        int d_t = packetCount - pktCntNvlRcvr + 1;
        
        ipDst_Mahoney_score = (float)d_t*n/d_r;
        
        std::cout << d_t << ":" << n << ":" << d_r << "\n";
        std::cout << packetCount << ": Anomaly score: " << ipDst_Mahoney_score << "\n";
    }
        */    
    // Write stats to file
      std::ofstream file;
      file.open ("ip_entropy.csv",std::ios_base::app);
      file << packetCount << "," << IPsSrcEntropy << "," << IPsDstEntropy << "\n";
      file.close();    
}

// Aidmar
void statistics::addFlowStat(std::string ipAddressSender,int sport,std::string ipAddressReceiver,int dport){
    std::cout<<ipAddressSender<<":"<<sport<<","<<ipAddressReceiver<<":"<<dport<<"\n";
    
    // if already exist A(ipAddressReceiver, dport), B(ipAddressSender, sport)
    /*if (flow_statistics.count({ipAddressReceiver, dport, ipAddressSender, sport})>0){
        flow_statistics[{ipAddressReceiver, dport, ipAddressSender, sport}].pkts_B_A++;
        std::cout<<flow_statistics[{ipAddressReceiver, dport, ipAddressSender, sport}].pkts_A_B<<"\n";
        std::cout<<flow_statistics[{ipAddressReceiver, dport, ipAddressSender, sport}].pkts_B_A<<"\n";
    }
    else{*/
    std::cout<<flow_statistics[{ipAddressSender, sport, ipAddressReceiver, dport}].pkts_A_B<<"\n";
        flow_statistics[{ipAddressSender, sport, ipAddressReceiver, dport}].pkts_A_B++;
        std::cout<<flow_statistics[{ipAddressSender, sport, ipAddressReceiver, dport}].pkts_A_B<<"\n";
        std::cout<<flow_statistics[{ipAddressSender, sport, ipAddressReceiver, dport}].pkts_B_A<<"\n";
    //}      
    
}
    
    
// Aidmar
/**
 * Increments the packet counter for the given IP address and MSS value.
 * @param ipAddress The IP address whose MSS packet counter should be incremented.
 * @param mssValue The MSS value of the packet.
 */
void statistics::incrementMSScount(std::string ipAddress, int mssValue) {
    mss_distribution[{ipAddress, mssValue}]++;
}

// Aidmar
/**
 * Increments the packet counter for the given IP address and window size.
 * @param ipAddress The IP address whose window size packet counter should be incremented.
 * @param winSize The window size of the packet.
 */
void statistics::incrementWinCount(std::string ipAddress, int winSize) {
    win_distribution[{ipAddress, winSize}]++;
}

/**
 * Increments the packet counter for the given IP address and TTL value.
 * @param ipAddress The IP address whose TTL packet counter should be incremented.
 * @param ttlValue The TTL value of the packet.
 */
void statistics::incrementTTLcount(std::string ipAddress, int ttlValue) {
    ttl_distribution[{ipAddress, ttlValue}]++;
}

/**
 * Increments the protocol counter for the given IP address and protocol.
 * @param ipAddress The IP address whose protocol packet counter should be incremented.
 * @param protocol The protocol of the packet.
 */
void statistics::incrementProtocolCount(std::string ipAddress, std::string protocol) {
    protocol_distribution[{ipAddress, protocol}]++;
}

/**
 * Returns the number of packets seen for the given IP address and protocol.
 * @param ipAddress The IP address whose packet count is wanted.
 * @param protocol The protocol whose packet count is wanted.
 * @return an integer: the number of packets
 */
int statistics::getProtocolCount(std::string ipAddress, std::string protocol) {
    return protocol_distribution[{ipAddress, protocol}];
}

/**
 * Increments the packet counter for
 * - the given sender IP address with outgoing port and
 * - the given receiver IP address with incoming port.
 * @param ipAddressSender The IP address of the packet sender.
 * @param outgoingPort The port used by the sender.
 * @param ipAddressReceiver The IP address of the packet receiver.
 * @param incomingPort The port used by the receiver.
 */
void statistics::incrementPortCount(std::string ipAddressSender, int outgoingPort, std::string ipAddressReceiver,
                                    int incomingPort) {
    ip_ports[{ipAddressSender, "out", outgoingPort}]++;
    ip_ports[{ipAddressReceiver, "in", incomingPort}]++;
}

/**
 * Creates a new statistics object.
 */
statistics::statistics(void) {
}

/**
 * Stores the assignment IP address -> MAC address.
 * @param ipAddress The IP address belonging to the given MAC address.
 * @param macAddress The MAC address belonging to the given IP address.
 */
void statistics::assignMacAddress(std::string ipAddress, std::string macAddress) {
    ip_mac_mapping[ipAddress] = macAddress;
}

/**
 * Registers statistical data for a sent packet. Increments the counter packets_sent for the sender and
 * packets_received for the receiver. Adds the bytes as kbytes_sent (sender) and kybtes_received (receiver).
 * @param ipAddressSender The IP address of the packet sender.
 * @param ipAddressReceiver The IP address of the packet receiver.
 * @param bytesSent The packet's size.
 */
void statistics::addIpStat_packetSent(std::string ipAddressSender, std::string ipAddressReceiver, long bytesSent) {
    // Aidmar - Adding IP as a sender for first time
    if(ip_statistics[ipAddressSender].pkts_sent==0){  
        // Caculate Mahoney anomaly score for ip.src
        float ipSrc_Mahoney_score = 0;
        // s_r: The number of IP sources (the different values)
        // n: The number of the total instances
        // s_t: The "time" since last anomalous (novel) IP was appeared
        int s_t = 0, n = 0, s_r = 0;
        
        for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
                if (i->second.pkts_sent > 0)
                    s_r++;
            }
        if(s_r > 0){
            // The number of the total instances
            n = packetCount;
            // The packet count when the last novel IP was added as a sender
            int pktCntNvlSndr = 0;
            for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
                if (pktCntNvlSndr < i->second.firstAppearAsSenderPktCount)
                    pktCntNvlSndr = i->second.firstAppearAsSenderPktCount;
            }
            // The "time" since last anomalous (novel) IP was appeared
            s_t = packetCount - pktCntNvlSndr + 1;
        
            ipSrc_Mahoney_score = (float)s_t*n/s_r;
        }
        
    // Write stats to file
    std::ofstream file;
    file.open ("ip_src_anomaly_score.csv",std::ios_base::app);
    file << ipAddressSender << ","<< s_t << "," << n << "," << s_r << "," << ipSrc_Mahoney_score << "\n";
    file.close();
    
    ip_statistics[ipAddressSender].firstAppearAsSenderPktCount = packetCount;  
    ip_statistics[ipAddressSender].sourceAnomalyScore = ipSrc_Mahoney_score;
    
    }
    // Aidmar - Adding IP as a receiver for first time
    if(ip_statistics[ipAddressReceiver].pkts_received==0){
        // Caculate Mahoney anomaly score for ip.dst
        float ipDst_Mahoney_score = 0;
        // s_r: The number of IP sources (the different values)
        // n: The number of the total instances
        // s_t: The "time" since last anomalous (novel) IP was appeared
        int s_t = 0, n = 0, s_r = 0;
        
        for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
                if (i->second.pkts_received > 0)
                    s_r++;
            }
        if(s_r > 0){
            // The number of the total instances
            n = packetCount;
            // The packet count when the last novel IP was added as a sender
            int pktCntNvlRcvr = 0;
            for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
                if (pktCntNvlRcvr < i->second.firstAppearAsReceiverPktCount)
                    pktCntNvlRcvr = i->second.firstAppearAsReceiverPktCount;
            }
            // The "time" since last anomalous (novel) IP was appeared
            s_t = packetCount - pktCntNvlRcvr + 1;
        
            ipDst_Mahoney_score = (float)s_t*n/s_r;
        }
        
    // Write stats to file
    std::ofstream file;
    file.open ("ip_dst_anomaly_score.csv",std::ios_base::app);
    file << ipAddressReceiver << ","<< s_t << "," << n << "," << s_r << "," << ipDst_Mahoney_score << "\n";
    file.close();
        
    ip_statistics[ipAddressReceiver].firstAppearAsReceiverPktCount = packetCount;
    ip_statistics[ipAddressReceiver].destinationAnomalyScore = ipDst_Mahoney_score;
    }
    
    // Update stats for packet sender
    ip_statistics[ipAddressSender].kbytes_sent += (float(bytesSent) / 1024);
    ip_statistics[ipAddressSender].pkts_sent++;
    // Update stats for packet receiver
    ip_statistics[ipAddressReceiver].kbytes_received += (float(bytesSent) / 1024);
    ip_statistics[ipAddressReceiver].pkts_received++;        
}

/**
 * Registers a value of the TCP option Maximum Segment Size (MSS).
 * @param ipAddress The IP address which sent the TCP packet.
 * @param MSSvalue The MSS value found.
 */
void statistics::addMSS(std::string ipAddress, int MSSvalue) {
    ip_sumMss[ipAddress] += MSSvalue;
}

/**
 * Setter for the timestamp_firstPacket field.
 * @param ts The timestamp of the first packet in the PCAP file.
 */
void statistics::setTimestampFirstPacket(Tins::Timestamp ts) {
    timestamp_firstPacket = ts;
}

/**
 * Setter for the timestamp_lastPacket field.
 * @param ts The timestamp of the last packet in the PCAP file.
 */
void statistics::setTimestampLastPacket(Tins::Timestamp ts) {
    timestamp_lastPacket = ts;
}

/**
 * Calculates the capture duration.
 * @return a formatted string HH:MM:SS.mmmmmm with
 * HH: hour, MM: minute, SS: second, mmmmmm: microseconds
 */
std::string statistics::getCaptureDurationTimestamp() const {
    // Calculate duration
    time_t t = (timestamp_lastPacket.seconds() - timestamp_firstPacket.seconds());
    time_t ms = (timestamp_lastPacket.microseconds() - timestamp_firstPacket.microseconds());
    long int hour = t / 3600;
    long int remainder = (t - hour * 3600);
    long int minute = remainder / 60;
    long int second = (remainder - minute * 60) % 60;
    long int microseconds = ms;
    // Build desired output format: YYYY-mm-dd hh:mm:ss
    char out[64];
    sprintf(out, "%02ld:%02ld:%02ld.%06ld ", hour, minute, second, microseconds);
    return std::string(out);
}

/**
 * Calculates the capture duration.
 * @return a formatted string SS.mmmmmm with
 * S: seconds (UNIX time), mmmmmm: microseconds
 */
float statistics::getCaptureDurationSeconds() const {
    timeval d;
    d.tv_sec = timestamp_lastPacket.seconds() - timestamp_firstPacket.seconds();
    d.tv_usec = timestamp_lastPacket.microseconds() - timestamp_firstPacket.microseconds();
    char tmbuf[64], buf[64];
    auto nowtm = localtime(&(d.tv_sec));
    strftime(tmbuf, sizeof(tmbuf), "%S", nowtm);
    snprintf(buf, sizeof(buf), "%s.%06u", tmbuf, (uint) d.tv_usec);
    return std::stof(std::string(buf));
}

/**
 * Creates a timestamp based on a time_t seconds (UNIX time format) and microseconds.
 * @param seconds
 * @param microseconds
 * @return a formatted string Y-m-d H:M:S.m with
 * Y: year, m: month, d: day, H: hour, M: minute, S: second, m: microseconds
 */
std::string statistics::getFormattedTimestamp(time_t seconds, suseconds_t microseconds) const {
    timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = microseconds;
    char tmbuf[64], buf[64];
    auto nowtm = localtime(&(tv.tv_sec));
    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buf, sizeof(buf), "%s.%06u", tmbuf, (uint) tv.tv_usec);
    return std::string(buf);
}

/**
 * Calculates the statistics for a given IP address.
 * @param ipAddress The IP address whose statistics should be calculated.
 * @return a ip_stats struct containing statistical data derived by the statistical data collected.
 */
ip_stats statistics::getStatsForIP(std::string ipAddress) {
    float duration = getCaptureDurationSeconds();
    entry_ipStat ipStatEntry = ip_statistics[ipAddress];

    ip_stats s;
    s.bandwidthKBitsIn = (ipStatEntry.kbytes_received / duration) * 8;
    s.bandwidthKBitsOut = (ipStatEntry.kbytes_sent / duration) * 8;
    s.packetPerSecondIn = (ipStatEntry.pkts_received / duration);
    s.packetPerSecondOut = (ipStatEntry.pkts_sent / duration);
    s.AvgPacketSizeSent = (ipStatEntry.kbytes_sent / ipStatEntry.pkts_sent);
    s.AvgPacketSizeRecv = (ipStatEntry.kbytes_received / ipStatEntry.pkts_received);
    int sumMSS = ip_sumMss[ipAddress];
    int tcpPacketsSent = getProtocolCount(ipAddress, "TCP");
    s.AvgMaxSegmentSizeTCP = ((sumMSS > 0 && tcpPacketsSent > 0) ? (sumMSS / tcpPacketsSent) : 0);

    return s;
}

/**
 * Increments the packet counter.
 */
void statistics::incrementPacketCount() {
    packetCount++;
}

/**
 * Prints the statistics of the PCAP and IP specific statistics for the given IP address.
 * @param ipAddress The IP address whose statistics should be printed. Can be empty "" to print only general file statistics.
 */
void statistics::printStats(std::string ipAddress) {
    std::stringstream ss;
    ss << std::endl;
    ss << "Capture duration: " << getCaptureDurationSeconds() << " seconds" << std::endl;
    ss << "Capture duration (HH:MM:SS.mmmmmm): " << getCaptureDurationTimestamp() << std::endl;
    ss << "#Packets: " << packetCount << std::endl;
    ss << std::endl;

    // Print IP address specific statistics only if IP address was given
    if (ipAddress != "") {
        entry_ipStat e = ip_statistics[ipAddress];
        ss << "\n----- STATS FOR IP ADDRESS [" << ipAddress << "] -------" << std::endl;
        ss << std::endl << "KBytes sent: " << e.kbytes_sent << std::endl;
        ss << "KBytes received: " << e.kbytes_received << std::endl;
        ss << "Packets sent: " << e.pkts_sent << std::endl;
        ss << "Packets received: " << e.pkts_received << "\n\n";

        ip_stats is = getStatsForIP(ipAddress);
        ss << "Bandwidth IN: " << is.bandwidthKBitsIn << " kbit/s" << std::endl;
        ss << "Bandwidth OUT: " << is.bandwidthKBitsOut << " kbit/s" << std::endl;
        ss << "Packets per second IN: " << is.packetPerSecondIn << std::endl;
        ss << "Packets per second OUT: " << is.packetPerSecondOut << std::endl;
        ss << "Avg Packet Size Sent: " << is.AvgPacketSizeSent << " kbytes" << std::endl;
        ss << "Avg Packet Size Received: " << is.AvgPacketSizeRecv << " kbytes" << std::endl;
        ss << "Avg MSS: " << is.AvgMaxSegmentSizeTCP << " bytes" << std::endl;
    }
    std::cout << ss.str();
}

/**
 * Derives general PCAP file statistics from the collected statistical data and
 * writes all data into a SQLite database, located at database_path.
 * @param database_path The path of the SQLite database file ending with .sqlite3.
 */
void statistics::writeToDatabase(std::string database_path) {
    // Generate general file statistics
    float duration = getCaptureDurationSeconds();
    long sumPacketsSent = 0, senderCountIP = 0;
    float sumBandwidthIn = 0.0, sumBandwidthOut = 0.0;
    for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
        sumPacketsSent += i->second.pkts_sent;
        // Consumed bandwith (bytes) for sending packets
        sumBandwidthIn += (i->second.kbytes_received / duration);
        sumBandwidthOut += (i->second.kbytes_sent / duration);
        senderCountIP++;
    }

    float avgPacketRate = (packetCount / duration);
    long avgPacketSize = getAvgPacketSize();
    long avgPacketsSentPerHost = (sumPacketsSent / senderCountIP);
    float avgBandwidthInKBits = (sumBandwidthIn / senderCountIP) * 8;
    float avgBandwidthOutInKBits = (sumBandwidthOut / senderCountIP) * 8;

    // Create database and write information
    statistics_db db(database_path);
    db.writeStatisticsFile(packetCount, getCaptureDurationSeconds(),
                           getFormattedTimestamp(timestamp_firstPacket.seconds(), timestamp_firstPacket.microseconds()),
                           getFormattedTimestamp(timestamp_lastPacket.seconds(), timestamp_lastPacket.microseconds()),
                           avgPacketRate, avgPacketSize, avgPacketsSentPerHost, avgBandwidthInKBits,
                           avgBandwidthOutInKBits);
    db.writeStatisticsIP(ip_statistics);
    db.writeStatisticsTTL(ttl_distribution);
    db.writeStatisticsIpMac(ip_mac_mapping);
    db.writeStatisticsMss(ip_sumMss);
    db.writeStatisticsPorts(ip_ports);
    db.writeStatisticsProtocols(protocol_distribution);
    // Aidmar
    db.writeStatisticsMss_dist(mss_distribution);
    db.writeStatisticsWin(win_distribution);
    db.writeStatisticsFlow(flow_statistics);
}

/**
 * Returns the average packet size.
 * @return a float indicating the average packet size in kbytes.
 */
float statistics::getAvgPacketSize() const {
    // AvgPktSize = (Sum of all packet sizes / #Packets)
    return (sumPacketSize / packetCount) / 1024;
}

/**
 * Adds the size of a packet (to be used to calculate the avg. packet size).
 * @param packetSize The size of the current packet in bytes.
 */
void statistics::addPacketSize(uint32_t packetSize) {
    sumPacketSize += ((float) packetSize);
}






































