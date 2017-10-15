#include <iostream>
#include <fstream>
#include <vector>
#include <math.h>
#include "statistics.h"
#include <sstream>
#include <SQLiteCpp/SQLiteCpp.h>
#include "statistics_db.h"
#include "statistics.h"
#include "utilities.h"

using namespace Tins;

/**
 * Checks if there is a payload and increments payloads counter.
 * @param pdu_l4 The packet that should be checked if it has a payload or not.
 */
void statistics::checkPayload(const PDU *pdu_l4) {
    if(this->getDoExtraTests()) {
        // pdu_l4: Tarnsport layer 4
        int pktSize = pdu_l4->size();
        int headerSize = pdu_l4->header_size(); // TCP/UDP header
        int payloadSize = pktSize - headerSize;
        if (payloadSize > 0)
            payloadCount++;
    }
}

/**
 * Checks the correctness of TCP checksum and increments counter if the checksum was incorrect.
 * @param ipAddressSender The source IP.
 * @param ipAddressReceiver The destination IP.
 * @param tcpPkt The packet to get checked.
 */
void statistics::checkTCPChecksum(std::string ipAddressSender, std::string ipAddressReceiver, TCP tcpPkt) {
    if(this->getDoExtraTests()) {
        if(check_tcpChecksum(ipAddressSender, ipAddressReceiver, tcpPkt))
            correctTCPChecksumCount++;
        else incorrectTCPChecksumCount++;
    }
}

/**
 * Calculates entropy of the source and destination IPs in a time interval.
 * @param intervalStartTimestamp The timstamp where the interval starts.
 * @return a vector: contains source IP entropy and destination IP entropy.
 */
std::vector<float> statistics::calculateLastIntervalIPsEntropy(std::chrono::microseconds intervalStartTimestamp){
    if(this->getDoExtraTests()) {
        std::vector<int> IPsSrcPktsCounts;
        std::vector<int> IPsDstPktsCounts;

        std::vector<float> IPsSrcProb;
        std::vector<float> IPsDstProb;

        int pktsSent = 0, pktsReceived = 0;

        for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
            int IPsSrcPktsCount = 0;
            for (auto j = i->second.pkts_sent_timestamp.begin(); j != i->second.pkts_sent_timestamp.end(); j++) {
                if(*j >= intervalStartTimestamp)
                    IPsSrcPktsCount++;
            }
            if(IPsSrcPktsCount != 0) {
                IPsSrcPktsCounts.push_back(IPsSrcPktsCount);
                pktsSent += IPsSrcPktsCount;
            }

            int IPsDstPktsCount = 0;
            for (auto j = i->second.pkts_received_timestamp.begin(); j != i->second.pkts_received_timestamp.end(); j++) {
                if(*j >= intervalStartTimestamp)
                    IPsDstPktsCount++;
            }
            if(IPsDstPktsCount != 0) {
                IPsDstPktsCounts.push_back(IPsDstPktsCount);
                pktsReceived += IPsDstPktsCount;
            }
        }

        for (auto i = IPsSrcPktsCounts.begin(); i != IPsSrcPktsCounts.end(); i++) {
            IPsSrcProb.push_back((float) *i / pktsSent);
        }
        for (auto i = IPsDstPktsCounts.begin(); i != IPsDstPktsCounts.end(); i++) {
            IPsDstProb.push_back((float) *i / pktsReceived);
        }

        // Calculate IP source entropy
        float IPsSrcEntropy = 0;
        for (unsigned i = 0; i < IPsSrcProb.size(); i++) {
            if (IPsSrcProb[i] > 0)
                IPsSrcEntropy += -IPsSrcProb[i] * log2(IPsSrcProb[i]);
        }
        // Calculate IP destination entropy
        float IPsDstEntropy = 0;
        for (unsigned i = 0; i < IPsDstProb.size(); i++) {
            if (IPsDstProb[i] > 0)
                IPsDstEntropy += -IPsDstProb[i] * log2(IPsDstProb[i]);
        }

        std::vector<float> entropies = {IPsSrcEntropy, IPsDstEntropy};
        return entropies;
    }
    else {
        return {-1, -1};
    }
}


/**
 * Calculates the cumulative entropy of the source and destination IPs, i.e., the entropy for packets from the beginning of the pcap file.
 * @return a vector: contains the cumulative entropies of source and destination IPs
 */
std::vector<float> statistics::calculateIPsCumEntropy(){
    if(this->getDoExtraTests()) {
        std::vector <std::string> IPs;
        std::vector <float> IPsSrcProb;
        std::vector <float> IPsDstProb;

        for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
            IPs.push_back(i->first);
            IPsSrcProb.push_back((float)i->second.pkts_sent/packetCount);
            IPsDstProb.push_back((float)i->second.pkts_received/packetCount);
        }

        // Calculate IP source entropy
        float IPsSrcEntropy = 0;
        for(unsigned i=0; i < IPsSrcProb.size();i++){
            if (IPsSrcProb[i] > 0)
                IPsSrcEntropy += - IPsSrcProb[i]*log2(IPsSrcProb[i]);
        }

        // Calculate IP destination entropy
        float IPsDstEntropy = 0;
        for(unsigned i=0; i < IPsDstProb.size();i++){
            if (IPsDstProb[i] > 0)
                IPsDstEntropy += - IPsDstProb[i]*log2(IPsDstProb[i]);
        }

        std::vector<float> entropies = {IPsSrcEntropy, IPsDstEntropy};
        return entropies;
    }
    else {
    return {-1, -1};
    }
}

/**
 * Calculates sending packet rate for each IP in a time interval. Finds min and max packet rate and adds them to ip_statistics map.
 * @param intervalStartTimestamp The timstamp where the interval starts.
 */
void statistics::calculateIPIntervalPacketRate(std::chrono::duration<int, std::micro> interval, std::chrono::microseconds intervalStartTimestamp){        
        for (auto i = ip_statistics.begin(); i != ip_statistics.end(); i++) {
                int indexStartSent = getClosestIndex(i->second.pkts_sent_timestamp, intervalStartTimestamp);
                int IPsSrcPktsCount = i->second.pkts_sent_timestamp.size() - indexStartSent;
                float interval_pkt_rate = (float) IPsSrcPktsCount * 1000000 / interval.count(); // used 10^6 because interval in microseconds
                i->second.interval_pkt_rate.push_back(interval_pkt_rate);
                if(interval_pkt_rate > i->second.max_interval_pkt_rate || i->second.max_interval_pkt_rate == 0)
                    i->second.max_interval_pkt_rate = interval_pkt_rate;
                if(interval_pkt_rate < i->second.min_interval_pkt_rate || i->second.min_interval_pkt_rate == 0)
                    i->second.min_interval_pkt_rate = interval_pkt_rate;
        }
}

/**
 * Registers statistical data for a time interval.
 * @param intervalStartTimestamp The timstamp where the interval starts.
 * @param intervalEndTimestamp The timstamp where the interval ends.
 * @param previousPacketCount The total number of packets in last interval.
 */
void statistics::addIntervalStat(std::chrono::duration<int, std::micro> interval, std::chrono::microseconds intervalStartTimestamp, std::chrono::microseconds intervalEndTimestamp){
    // Add packet rate for each IP to ip_statistics map
    calculateIPIntervalPacketRate(interval, intervalStartTimestamp);
    
    std::vector<float> ipEntopies = calculateLastIntervalIPsEntropy(intervalStartTimestamp);
    std::vector<float> ipCumEntopies = calculateIPsCumEntropy();
    std::string lastPktTimestamp_s = std::to_string(intervalEndTimestamp.count());
    std::string  intervalStartTimestamp_s = std::to_string(intervalStartTimestamp.count());

    // The intervalStartTimestamp_s is the previous interval lastPktTimestamp_s
    interval_statistics[lastPktTimestamp_s].pkts_count = packetCount - intervalCumPktCount;
    interval_statistics[lastPktTimestamp_s].kbytes = (float(sumPacketSize - intervalCumSumPktSize) / 1024);

    interval_statistics[lastPktTimestamp_s].payload_count = payloadCount - intervalPayloadCount;
    interval_statistics[lastPktTimestamp_s].incorrect_tcp_checksum_count = incorrectTCPChecksumCount - intervalIncorrectTCPChecksumCount;
    interval_statistics[lastPktTimestamp_s].correct_tcp_checksum_count = correctTCPChecksumCount - intervalCorrectTCPChecksumCount;
    interval_statistics[lastPktTimestamp_s].novel_ip_count = ip_statistics.size() - intervalCumNewIPCount;
    interval_statistics[lastPktTimestamp_s].novel_ttl_count = ttl_values.size() - intervalCumNewTTLCount;
    interval_statistics[lastPktTimestamp_s].novel_win_size_count = win_values.size() - intervalCumNewWinSizeCount;
    interval_statistics[lastPktTimestamp_s].novel_tos_count = tos_values.size() - intervalCumNewToSCount;
    interval_statistics[lastPktTimestamp_s].novel_mss_count = mss_values.size() - intervalCumNewMSSCount;

    intervalPayloadCount = payloadCount;
    intervalIncorrectTCPChecksumCount = incorrectTCPChecksumCount;
    intervalCorrectTCPChecksumCount = correctTCPChecksumCount;
    intervalCumPktCount = packetCount;
    intervalCumSumPktSize = sumPacketSize;
    intervalCumNewIPCount =  ip_statistics.size();
    intervalCumNewTTLCount = ttl_values.size();
    intervalCumNewWinSizeCount = win_values.size();
    intervalCumNewToSCount = tos_values.size();
    intervalCumNewMSSCount = mss_values.size();

    if(ipEntopies.size()>1){
        interval_statistics[lastPktTimestamp_s].ip_src_entropy = ipEntopies[0];
        interval_statistics[lastPktTimestamp_s].ip_dst_entropy = ipEntopies[1];
    }
    if(ipCumEntopies.size()>1){
        interval_statistics[lastPktTimestamp_s].ip_src_cum_entropy = ipCumEntopies[0];
        interval_statistics[lastPktTimestamp_s].ip_dst_cum_entropy = ipCumEntopies[1];
    }
}        

/**
 * Registers statistical data for a sent packet in a given conversation (two IPs, two ports). 
 * Increments the counter packets_A_B or packets_B_A.
 * Adds the timestamp of the packet in pkts_A_B_timestamp or pkts_B_A_timestamp.
 * @param ipAddressSender The sender IP address.
 * @param sport The source port.
 * @param ipAddressReceiver The receiver IP address.
 * @param dport The destination port.
 * @param timestamp The timestamp of the packet.
 */
void statistics::addConvStat(std::string ipAddressSender,int sport,std::string ipAddressReceiver,int dport, std::chrono::microseconds timestamp){

    conv f1 = {ipAddressReceiver, dport, ipAddressSender, sport};
    conv f2 = {ipAddressSender, sport, ipAddressReceiver, dport};

    // if already exist A(ipAddressReceiver, dport), B(ipAddressSender, sport) conversation
    if (conv_statistics.count(f1)>0){
        conv_statistics[f1].pkts_count++;
        if(conv_statistics[f1].pkts_count<=3)
            conv_statistics[f1].interarrival_time.push_back(std::chrono::duration_cast<std::chrono::microseconds> (timestamp - conv_statistics[f1].pkts_timestamp.back()));
        conv_statistics[f1].pkts_timestamp.push_back(timestamp);
    }
    // Add new conversation A(ipAddressSender, sport), B(ipAddressReceiver, dport)
    else{
        conv_statistics[f2].pkts_count++;
        if(conv_statistics[f2].pkts_timestamp.size()>0 && conv_statistics[f2].pkts_count<=3 )
            conv_statistics[f2].interarrival_time.push_back(std::chrono::duration_cast<std::chrono::microseconds> (timestamp - conv_statistics[f2].pkts_timestamp.back()));
        conv_statistics[f2].pkts_timestamp.push_back(timestamp);
    }
}

/**
 * Increments the packet counter for the given IP address and MSS value.
 * @param ipAddress The IP address whose MSS packet counter should be incremented.
 * @param mssValue The MSS value of the packet.
 */
void statistics::incrementMSScount(std::string ipAddress, int mssValue) {
    mss_values[mssValue]++;
    mss_distribution[{ipAddress, mssValue}]++;
}

/**
 * Increments the packet counter for the given IP address and window size.
 * @param ipAddress The IP address whose window size packet counter should be incremented.
 * @param winSize The window size of the packet.
 */
void statistics::incrementWinCount(std::string ipAddress, int winSize) {
    win_values[winSize]++;
    win_distribution[{ipAddress, winSize}]++;
}

/**
 * Increments the packet counter for the given IP address and TTL value.
 * @param ipAddress The IP address whose TTL packet counter should be incremented.
 * @param ttlValue The TTL value of the packet.
 */
void statistics::incrementTTLcount(std::string ipAddress, int ttlValue) {
    ttl_values[ttlValue]++;
    ttl_distribution[{ipAddress, ttlValue}]++;
}

/**
 * Increments the packet counter for the given IP address and ToS value.
 * @param ipAddress The IP address whose ToS packet counter should be incremented.
 * @param tosValue The ToS value of the packet.
 */
void statistics::incrementToScount(std::string ipAddress, int tosValue) {
    tos_values[tosValue]++;
    tos_distribution[{ipAddress, tosValue}]++;
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
void statistics::addIpStat_packetSent(std::string filePath, std::string ipAddressSender, std::string ipAddressReceiver, long bytesSent, std::chrono::microseconds timestamp) {

    // Adding IP as a sender for first time
    if(ip_statistics[ipAddressSender].pkts_sent==0){  
        // Add the IP class
        ip_statistics[ipAddressSender].ip_class = getIPv4Class(ipAddressSender);
    }
    
    // Adding IP as a receiver for first time
    if(ip_statistics[ipAddressReceiver].pkts_received==0){
        // Add the IP class
        ip_statistics[ipAddressReceiver].ip_class = getIPv4Class(ipAddressReceiver);
    }

    // Update stats for packet sender
    ip_statistics[ipAddressSender].kbytes_sent += (float(bytesSent) / 1024);
    ip_statistics[ipAddressSender].pkts_sent++;
    ip_statistics[ipAddressSender].pkts_sent_timestamp.push_back(timestamp);
                
    // Update stats for packet receiver
    ip_statistics[ipAddressReceiver].kbytes_received += (float(bytesSent) / 1024);
    ip_statistics[ipAddressReceiver].pkts_received++;
    ip_statistics[ipAddressReceiver].pkts_received_timestamp.push_back(timestamp);
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
 * Getter for the timestamp_firstPacket field.
 */
Tins::Timestamp statistics::getTimestampFirstPacket() {
    return timestamp_firstPacket;
}

/**
 * Getter for the timestamp_lastPacket field.
 */
Tins::Timestamp statistics::getTimestampLastPacket() {
    return timestamp_lastPacket;
}

/**
 * Getter for the packetCount field.
 */
int statistics::getPacketCount() {
    return packetCount;
}

/**
 * Getter for the sumPacketSize field.
 */
int statistics::getSumPacketSize() {
    return sumPacketSize;
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

/**
 * Setter for the doExtraTests field.
 */
void statistics::setDoExtraTests(bool var) {
    doExtraTests = var;
}

/**
 * Getter for the doExtraTests field.
 */
bool statistics::getDoExtraTests() {
    return doExtraTests;
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
    if(senderCountIP>0) {
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
        db.writeStatisticsPorts(ip_ports);
        db.writeStatisticsProtocols(protocol_distribution);
        db.writeStatisticsMSS(mss_distribution);
        db.writeStatisticsToS(tos_distribution);
        db.writeStatisticsWin(win_distribution);
        db.writeStatisticsConv(conv_statistics);
        db.writeStatisticsInterval(interval_statistics);
    }
    else {
        // Tinslib failed to recognize the types of the packets in the input PCAP
        std::cout<<"ERROR: Statistics could not be collected from the input PCAP!"<<"\n";
        return;
    }
}







































