/*
 * Class for processing messages containing abstract Membership Management Communication.
 * A message has to consist of (namely): Src, Dst, Type, Time.
 */

#ifndef BOTNET_COMM_PROCESSOR_H
#define BOTNET_COMM_PROCESSOR_H

#include <iostream>
#include <pybind11/pybind11.h>
#include <vector>
#include <thread>
#include <deque>
#include <set>
#include <future>
#include <fstream>
#include <string>
#include <istream>
#include <iomanip>


/*
 * Botnet communication types (equal to the ones contained in the MessageType class in MembersMgmtCommAttack.py)
 */
#define TIMEOUT 3
#define SALITY_NL_REQUEST 101
#define SALITY_NL_REPLY 102
#define SALITY_HELLO 103
#define SALITY_HELLO_REPLY 104

/*
 * Needed because of machine inprecision. E.g a time difference of 0.1s is stored as >0.1s
 */
#define EPS_TOLERANCE 1e-12  // works for a difference of 0.1

/*
 * For quick usage
 */
namespace py = pybind11;

/*
 * Definition of structs
 */

/*
 * Struct used as data structure to represent an abstract communication message:
 * - Source ID
 * - Destination ID
 * - Message type
 * - Time of message
 */
struct abstract_msg {
    // necessary constructors to have default values
    abstract_msg (unsigned int src, unsigned int dst, unsigned short type, double time, int line_no) :
    src(src), dst(dst), type(type), time(time), line_no(line_no) {}

    abstract_msg () {}

    // members
    unsigned int src = 0;
    unsigned int dst = 0;
    unsigned short type = 0; 
    double time = 0.0;
    int line_no = -1;
};

/*
 * Struct used as data structure to represent an interval of communication:
 * - A set of all initiator IDs contained in the interval
 * - The number of messages sent in the interval (excluding timeouts)
 * - The start index of the interval with respect to the member variable 'packets'
 * - The end index of the interval with respect to the member variable 'packets'
 */
struct comm_interval {
    std::set<unsigned int> ids;
    unsigned int comm_sum;
    unsigned int start_idx;
    unsigned int end_idx; 
};

/*
 * A greater than operator desgined to handle slight machine inprecision up to EPS_TOLERANCE.
 * @param a The first number
 * @param b The second number
 * @return true (1) if a > b, otherwise false(0)
*/
int greater_than(double a, double b){
    return b - a < -1 * EPS_TOLERANCE;
}


class botnet_comm_processor {

public:
    /*
    * Class constructor
    */
    botnet_comm_processor();

    botnet_comm_processor(const py::list &messages_pyboost);

    /*
     * Methods
     */
    py::dict find_interval_from_startidx(int start_idx, int number_ids, double max_int_time);

    py::dict find_interval_from_endidx(int end_idx, int number_ids, double max_int_time);

    py::list find_optimal_interval(int number_ids, double max_int_time);

    py::list get_interval_init_ids(int start_idx, int end_idx);

    py::list get_messages(unsigned int start_idx, unsigned int end_idx);

    int get_message_count();

    unsigned int parse_csv(const std::string &filepath);

    unsigned int parse_xml(const std::string &filepath);

    void set_messages(const py::list &messages_pyboost);

    std::string write_xml(const std::string &out_dir, const std::string &basename);

private:
    /*
     * Methods
     */
    py::list convert_intervals_to_py_repr(const std::vector<comm_interval>& intervals);

    void find_optimal_interval_helper(std::promise<std::vector<comm_interval> > && p, int number_ids, double max_int_time, int start_idx, int end_idx);

    int msgtype_is_request(unsigned short mtype);

    int msgtype_is_response(unsigned short mtype);

    // void print_message(const abstract_msg &message);

    void process_csv_attrib(abstract_msg &msg, const std::string &cur_word);

    void process_kv(abstract_msg &msg, const std::string &key, const std::string &value);

    void process_xml_attrib_assign(abstract_msg &msg, const std::string &cur_word);

    /*
     * Attributes
     */
    std::vector<abstract_msg> messages;
}; 


#endif //BOTNET_COMM_PROCESSOR_H
