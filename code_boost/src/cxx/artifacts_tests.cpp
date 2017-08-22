#include <iostream>
#include <fstream>
#include <sstream>

#include "artifacts_tests.h"


using namespace Tins;

/**
 * Creates a new artifacts_tests object.
 */
artifacts_tests::artifacts_tests() {
     correctChecksum = 0;
     incorrectChecksum= 0;
     checksumIncorrectRatio= 0;
    
     noPayloadCount= 0;
     payloadCount= 0;
}


/*
**************************************************************************
Function: tcp_sum_calc()
**************************************************************************
Description: 
	Calculate TCP checksum
***************************************************************************
*/

typedef unsigned short u16;
typedef unsigned long u32;

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


void convertIPv4toArray(std::string IP, unsigned short IP_bytes[]){
    std::vector<std::string> temp_v;
    split_str(IP,'.',temp_v);    
    IP_bytes[0] = std::stoi(temp_v[0]);
    IP_bytes[1] = std::stoi(temp_v[1]);
    IP_bytes[2] = std::stoi(temp_v[2]);
    IP_bytes[3] = std::stoi(temp_v[3]);
}

/**
 * Checks the TCP checksum of a given packet.
 * @param tcpPkt The packet to get checked.
 */
void artifacts_tests::check_checksum(std::string ipAddressSender, std::string ipAddressReceiver, TCP tcpPkt){
    uint16_t checksum = tcpPkt.checksum();
       
    unsigned short calculatedChecsum = 0;
    
    int headerSize = tcpPkt.header_size();

    std::vector<uint8_t> bufferArray_8 = tcpPkt.serialize();
    std::vector<unsigned short> bufferArray_16;
     for(int i=0; (unsigned)i<bufferArray_8.size();i++){
         bufferArray_16.push_back(bufferArray_8[i]);
       }

    /*for(int i=0; i<bufferArray_8.size();i+=2){
        uint8_t temp[2];
        temp[0] = bufferArray_8[i];
        if(i!=(bufferArray_8.size()-1))
            temp[1] = bufferArray_8[i+1];
        else
            temp[1] = 0;
        unsigned short n;
        memcpy(&n, temp, sizeof(unsigned short));
        bufferArray_16.push_back(n);
    } */  
        
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


    if(calculatedChecsum == checksum)
        correctChecksum++;
    else{
        std::cout<<"Sender:"<<ipAddressSender<<", Receiver:"<<ipAddressReceiver<<"\n";
        std::cout<<"Packet checksum:"<<checksum<<"\n";
        std::cout<<"Calculated checksum:"<<calculatedChecsum<<"\n";
         
        incorrectChecksum++;
    }
}

/**
 * Gets the ratio of incorrect TCP checksums to total number of TCP packets.
 */
float artifacts_tests::get_checksum_incorrect_ratio(){
    int totalPktsNum = incorrectChecksum+correctChecksum;
    float ratio = 0;
    if(totalPktsNum!=0)
        ratio = (float)incorrectChecksum/totalPktsNum;
    
    std::cout<<"Incorrect checksums: "<<incorrectChecksum<<"\n";
    std::cout<<"Total TCP packets: "<<totalPktsNum<<"\n";
    std::cout<<"get_checksum_incorrect_ratio: "<<ratio<<"\n";
    
    return ratio;
}

void artifacts_tests::check_payload(const PDU *pkt){
    int pktSize = pkt->size();
    int headerSize = pkt->header_size();
    int payloadSize = pktSize - headerSize;
    if(payloadSize>0)
        payloadCount++;
    else
        noPayloadCount++;
}

/**
 * Gets the ratio of packets that have payload to total number of packets.
 */
float artifacts_tests::get_payload_ratio(){
    int totalPktsNum = noPayloadCount+payloadCount;
    float ratio = 0;
    if(totalPktsNum!=0)
        ratio = (float)payloadCount/totalPktsNum;
    
    std::cout<<"Payload packets: "<<payloadCount<<"\n";
    std::cout<<"Total packets: "<<totalPktsNum<<"\n";
    std::cout<<"get_payload_ratio: "<<ratio<<"\n";
    
    return ratio;
}

void artifacts_tests::check_tos(uint8_t ToS){
    //if((unsigned)ToS != 0)
      //  std::cout<<"ToS: "<<(unsigned)ToS<<"\n";
}
