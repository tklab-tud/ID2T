// Created by Aidmar

#include "utilities.h"


/**
 * Split a string.
 * @param str string to be splitted 
 * @param delimiter delimiter to use in splitting
 * @return vector of substrings
 */
/*std::vector<std::string> split(std::string str, char delimiter) {
  std::vector<std::string> internal;
  std::stringstream ss(str); // Turn the string into a stream.
  std::string tok;  
  while(getline(ss, tok, delimiter)) {
    internal.push_back(tok);
  }  
  return internal;
}*/

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
