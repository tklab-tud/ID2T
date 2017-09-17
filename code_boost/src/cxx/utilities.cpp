// Created by Aidmar

#include "utilities.h"

using namespace Tins;

template<class T>
std::string integral_to_binary_string(T byte)
{
    std::bitset<sizeof(T) * CHAR_BIT> bs(byte);
    return bs.to_string();
}

/**
 * Split a string.
 * @param str string to be splitted 
 * @param delimiter delimiter to use in splitting
 * @return vector of substrings
 */
void split_str(const std::string& s, char delim,std::vector<std::string>& v) {
    auto i = 0;
    auto pos = s.find(delim);
    while (pos != std::string::npos) {
      v.push_back(s.substr(i, pos-i));
      i = ++pos;
      pos = s.find(delim, pos);

      if (pos == std::string::npos)
         v.push_back(s.substr(i, s.length()));
    }
}


/**
 * Get the class (A,B,C,D,E) of IP address.
 * @param ipAddress IP that we get its class
 */
std::string getIPv4Class(std::string ipAddress){
    std::string ipClass="Unknown";
    
    std::vector<std::string> ipBytes;
    split_str(ipAddress, '.',ipBytes);
    
    //std::cout<< ipAddress << "\n";
    
    if(ipBytes.size()>1){
    int b1 = std::stoi(ipBytes[0]);
    int b2 = std::stoi(ipBytes[1]);
    
    if(b1 >= 1 && b1 <= 126){
        if(b1 == 10)
            ipClass = "A-private";
        else
            ipClass = "A";
    }
    else if(b1 == 127){
        ipClass = "A-unused"; // cannot be used and is reserved for loopback and diagnostic functions.
    }
    else if (b1 >= 128 && b1 <= 191){
        if(b1 == 172 && b2 >= 16 && b2 <= 31) 
            ipClass = "B-private";
        else
            ipClass = "B";
    }
    else if (b1 >= 192 && b1 <= 223){
         if(b1 == 192 && b2 == 168) 
            ipClass = "C-private";
         else
            ipClass = "C";
    }
    else if (b1 >= 224 && b1 <= 239)
        ipClass = "D"; // Reserved for Multicasting
    else if (b1 >= 240 && b1 <= 254)
        ipClass = "E"; // Experimental; used for research    
    }
    /*
     // Could be done by using libtin IPv4Address
    IPv4Range range = IPv4Address("192.168.1.0") / 24;
    range.contains("192.168.1.250"); // Yey, it belongs to this network
    range.contains("192.168.0.100"); // NOPE
    */
    return ipClass;
}

/**
 * Get closest index for element in vector.
 * @param v vector
 * @param refElem element that we search for or for closest element
 */
int getClosestIndex(std::vector<std::chrono::microseconds> v, std::chrono::microseconds refElem)
{
    auto i = std::min_element(begin(v), end(v), [=] (std::chrono::microseconds x, std::chrono::microseconds y)
    {
        return std::abs((x - refElem).count()) < std::abs((y - refElem).count());
    });
    return std::distance(begin(v), i);
}

/**
 * Advance iterator by 100 steps.
 * @param iterator to advance
 */
void snifferIteratorIncrement(Tins::SnifferIterator& iterator){
    (((((((((iterator++)++)++)++)++)++)++)++)++)++;  
}


void convertIPv4toArray(std::string IP, unsigned short IP_bytes[]){
    std::vector<std::string> temp_v;
    split_str(IP,'.',temp_v);
    IP_bytes[0] = std::stoi(temp_v[0]);
    IP_bytes[1] = std::stoi(temp_v[1]);
    IP_bytes[2] = std::stoi(temp_v[2]);
    IP_bytes[3] = std::stoi(temp_v[3]);
}

//Calculate TCP checksum
u16 tcp_sum_calc(u16 len_tcp, u16 src_addr[],u16 dest_addr[], bool padding, u16 buff[])
{
    u16 prot_tcp=6;
    u16 padd=0;
    u16 word16;
    u32 sum;

    // Find out if the length of data is even or odd number. If odd,
    // add a padding byte = 0 at the end of packet
    //if ((padding&1)==1){
    if(padding){
        padd=1;
        buff[len_tcp]=0;
    }

    //initialize sum to zero
    sum=0;

    // make 16 bit words out of every two adjacent 8 bit words and
    // calculate the sum of all 16 vit words
    for (int i=0;i<len_tcp+padd;i=i+2){
        word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
        sum = sum + (unsigned long)word16;
    }
    // add the TCP pseudo header which contains:
    // the IP source and destinationn addresses,
    for (int i=0;i<4;i=i+2){
        word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
        sum=sum+word16;
    }
    for (int i=0;i<4;i=i+2){
        word16 =((dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
        sum=sum+word16;
    }
    // the protocol number and the length of the TCP packet
    sum = sum + prot_tcp + len_tcp;

    // keep only the last 16 bits of the 32 bit calculated sum and add the carries
    while (sum>>16)
        sum = (sum & 0xFFFF)+(sum >> 16);

    // Take the one's complement of sum
    sum = ~sum;

    return ((unsigned short) sum);
}

/**
 * Checks the TCP checksum of a given packet.
 * @param ipAddressSender The source IP.
 * @param ipAddressReceiver The destination IP.
 * @param tcpPkt The packet to get checked.
 */
bool check_tcpChecksum(std::string ipAddressSender, std::string ipAddressReceiver, TCP tcpPkt){
    uint16_t checksum = tcpPkt.checksum();

    unsigned short calculatedChecsum = 0;

    int headerSize = tcpPkt.header_size();
    std::vector<uint8_t> bufferArray_8;

    try {
        bufferArray_8 = tcpPkt.serialize();
    } catch (serialization_error) {
        std::cout << "Error: Could not serialize TCP packet with sender: " << ipAddressSender << ", receiver: "
                  << ipAddressReceiver << ", seq: " << tcpPkt.seq() << std::endl;
        return false;
    }

    std::vector<unsigned short> bufferArray_16;
    for(int i=0; (unsigned)i<bufferArray_8.size();i++){
        bufferArray_16.push_back(bufferArray_8[i]);
    }

    unsigned short* buff_16 = &bufferArray_16[0];
    unsigned short ipAddressSender_bytes[4];
    unsigned short ipAddressReceiver_bytes[4];
    convertIPv4toArray(ipAddressSender, ipAddressSender_bytes);
    convertIPv4toArray(ipAddressReceiver, ipAddressReceiver_bytes);

    //tcp_sum_calc(unsigned short len_tcp, unsigned short src_addr[],unsigned short dest_addr[], bool padding, unsigned short buff[])
    bool padding = false;
    int dataSize = bufferArray_8.size() - headerSize;  // TO-DO: why don't you use pkt.size()
    if(dataSize != 0)
        if(dataSize % 2 != 0)
            padding = true; // padding if the data size is odd

    calculatedChecsum = tcp_sum_calc(bufferArray_8.size(), ipAddressSender_bytes, ipAddressReceiver_bytes, padding, buff_16);

    return (calculatedChecsum == checksum);
}