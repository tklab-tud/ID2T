#ifndef UTILITIES_H
#define UTILITIES_H

#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <tins/tins.h>

// Aidmar
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

void split_str(const std::string& s, char delim,std::vector<std::string>& v);
std::string getIPv4Class(std::string ipAddress);
int getClosestIndex(std::vector<std::chrono::microseconds> v, std::chrono::microseconds refElem);
void snifferIteratorIncrement(Tins::SnifferIterator& iterator);

#endif //UTILITIES_H
