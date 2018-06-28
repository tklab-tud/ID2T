#include "botnet_comm_processor.h"
#include <algorithm>
#include <sstream>


/**
 * Creates a new botnet_comm_processor object. 
 * The abstract python messages are converted to easier-to-handle C++ data structures.
 * @param messages_pyboost The abstract communication messages 
 *    represented as (python) list containing (python) dicts.
 */
botnet_comm_processor::botnet_comm_processor(const py::list &messages_pyboost){
    set_messages(messages_pyboost);
}

/**
 * Creates a new and empty botnet_comm_processor object.
 */
botnet_comm_processor::botnet_comm_processor(){
}

/**
 * Set the messages of this communication processor.
 * @param messages_pyboost The abstract communication messages
 *    represented as (python) list containing (python) dicts.
 */
void botnet_comm_processor::set_messages(const py::list &messages_pyboost){
    messages.clear();
    for (size_t i = 0; i < len(messages_pyboost); i++){
        py::dict msg_pyboost = py::cast<py::dict>(messages_pyboost[i]);
        unsigned int src_id = std::stoi(py::cast<std::string>(msg_pyboost["Src"]));
        unsigned int dst_id = std::stoi(py::cast<std::string>(msg_pyboost["Dst"]));
        unsigned short type = (unsigned short) std::stoi(py::cast<std::string>(msg_pyboost["Type"]));
        double time = std::stod(py::cast<std::string>(msg_pyboost["Time"]));
        int line_no = std::stoi(msg_pyboost.contains("LineNumber") ? py::cast<std::string>(msg_pyboost["LineNumber"]) : "-1");

        abstract_msg msg = {src_id, dst_id, type, time, line_no};
        messages.push_back(std::move(msg));
    }
}

/**
 * Retrieve input information about message count.
 * @return the number of existing messages.
 */
int botnet_comm_processor::get_message_count(){
    return messages.size();
}

/**
 * Processes an XML attribute assignment. The result is reflected in the respective change of the given message.
 * @param msg The message this attribute refers to.
 * @param assignment The XML attribute assignment in notation: attribute="value"
 */
void botnet_comm_processor::process_xml_attrib_assign(abstract_msg &msg, const std::string &assignment) {
    std::size_t split_pos = assignment.find("=");
    if (split_pos != std::string::npos){
        std::string key = assignment.substr(0, split_pos);
        std::string value = assignment.substr(split_pos + 2, assignment.length() - 1);
        process_kv(msg, key, value);
    }
}

/**
 * Processes a key-value pair. The result is reflected in the respective change of the given message.
 * @param msg The message this kv pair refers to.
 * @param key The key of the attribute.
 * @param value The value of the attribute.
 */
void botnet_comm_processor::process_kv(abstract_msg &msg, const std::string &key, const std::string &value){
    if (key == "Src")
        msg.src = std::stoi(value);
    else if (key == "Dst")
        msg.dst = std::stoi(value);
    else if (key == "Type")
        msg.type = (unsigned short) std::stoi(value);
    else if (key == "Time")
        msg.time = std::stod(value);
    else if (key == "LineNumber")
        msg.line_no = std::stoi(value);
}

/**
 * Parses the packets contained in the given CSV to program structure.
 * @param filepath The filepath where the CSV is located.
 * @return The number of messages (or lines) contained in the CSV file.
 */
unsigned int botnet_comm_processor::parse_csv(const std::string &filepath){
    std::ifstream input(filepath);
    int line_no = 1;  // the first line has number 1

    messages.clear();
    // iterate over every line
    for (std::string line; std::getline(input, line); ){
        std::istringstream line_stream(line);
        abstract_msg cur_msg;
        cur_msg.line_no = line_no;
        // iterate over every key:value entry
        for (std::string pair; std::getline(line_stream, pair, ','); ){
            pair.erase(std::remove(pair.begin(), pair.end(), ' '), pair.end());
            std::size_t split_pos = pair.find(":");
            if (split_pos != std::string::npos){
                std::string key = pair.substr(0, split_pos);
                std::string value = pair.substr(split_pos + 1, pair.length());
                process_kv(cur_msg, key, value);
            }
        }
        messages.push_back(std::move(cur_msg));
        line_no++;
    }
    return messages.size();
}

/**
 * Parses the packets contained in the given XML to program structure.
 * @param filepath The filepath where the XML is located.
 * @return The number of messages contained in the XML file.
 */
unsigned int botnet_comm_processor::parse_xml(const std::string &filepath){
    std::ifstream input(filepath);
    std::string cur_word = "";
    abstract_msg cur_msg;
    char c;
    int read_packet_open = 0, read_slash = 0;

    messages.clear();
    // iterate over every character
    while (input.get(c)){
        if(c == '/')  // hints ending of tag
            read_slash = 1;
        else if (c == '>'){  // definitely closes tag
            if (read_packet_open && read_slash){  // handle oustanding attribute
                read_slash = 0;
                process_xml_attrib_assign(cur_msg, cur_word);
                messages.push_back(cur_msg);
                read_packet_open = 0;
            }
            cur_word = "";
        }
        else if (c == ' '){
            if (read_packet_open && cur_word != ""){  // handle new attribute
                process_xml_attrib_assign(cur_msg, cur_word);
            }
            else if (cur_word == "<packet")
                read_packet_open = 1;

            cur_word = "";
        }
        else
            cur_word += c;
    }
    return messages.size();
}

/**
 * Writes the communication messages contained in the class member messages into an XML file (with respective notation).
 * @param out_dir The directory the file is to be put in.
 * @param basename The actual name of the file without directories or extension.
 * @return The filepath of the written XML file.
 */
std::string botnet_comm_processor::write_xml(const std::string &out_dir, const std::string &basename){
    std::string filepath;
    if (out_dir[out_dir.length() - 1] == '/')
        filepath = out_dir + basename + ".xml";
    else
        filepath = out_dir + "/" + basename + ".xml";
    std::ofstream xml_file;
    xml_file.open(filepath);

    // set number of digits after dot to 11
    xml_file << std::fixed << std::setprecision(11);

    xml_file << "<trace name=\"" << basename << "\">";
    for (const auto &msg : messages){
        xml_file << "<packet ";
        xml_file << "Src=\"" << msg.src << "\" Dst=\"" << msg.dst << "\" ";
        xml_file << "Type=\"" << msg.type << "\" Time=\"" << msg.time << "\" ";
        xml_file << "LineNumber=\"" << msg.line_no << "\" />";
    }
    xml_file << "</trace>";

    xml_file.close();
    return filepath;
}

/**
 * Retrieves all messages contained in the interval between start_idx and end_idx in Python representation.
 * @param start_idx The inclusive first index of the interval.
 * @param end_idx The inclusive last index of the interval.
 * @return A (Python) list of (Python) dicts containing the desired information.
 */
py::list botnet_comm_processor::get_messages(unsigned int start_idx, unsigned int end_idx){
    py::list py_messages;
    for (std::size_t i = start_idx; i <= end_idx; i++){
        if (i >= messages.size())
            break;
        py::dict py_msg;
        py_msg["Src"] = messages[i].src;
        py_msg["Dst"] = messages[i].dst;
        py_msg["Type"] = messages[i].type;
        py_msg["Time"] = messages[i].time;
        py_msg["LineNumber"] = messages[i].line_no;
        py_messages.append(py_msg);
    }
    return py_messages;
}

/**
 * Finds the time interval(s) of maximum the given seconds with the most overall communication
 * (i.e. requests and responses) that has at least number_ids communicating initiators in it. 
 * @param number_ids The number of initiator IDs that have to exist in the interval(s).
 * @param max_int_time The maximum time period of the interval.
 * @return A (python) list of (python) dicts, where each dict (keys: 'IDs', Start', 'End') represents an interval with its
 * list of initiator IDs, a start index and an end index. The indices are with respect to the first abstract message.
 */
py::list botnet_comm_processor::find_optimal_interval(int number_ids, double max_int_time){
    unsigned int logical_thread_count = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;
    std::vector<std::future<std::vector<comm_interval> > > futures;

    // create as many threads as can run concurrently and assign them respective sections
    for (std::size_t i = 0; i < logical_thread_count; i++){
        unsigned int start_idx = (i * messages.size() / logical_thread_count);
        unsigned int end_idx = (i + 1) * messages.size() / logical_thread_count;
        std::promise<std::vector<comm_interval> > p;  // use promises to retrieve return values
        futures.push_back(p.get_future());
        threads.push_back(std::thread(&botnet_comm_processor::find_optimal_interval_helper, this, std::move(p), number_ids, max_int_time, start_idx, end_idx));
    }

    // synchronize all threads
    for (auto &t : threads){
        t.join();
    }

    // accumulate results
    std::vector<std::vector<comm_interval> > acc_possible_intervals;
    for (auto &f : futures){
        acc_possible_intervals.push_back(f.get());
    }

    // find overall most communicative interval
    std::vector<comm_interval> possible_intervals;
    unsigned int cur_highest_sum = 0;
    for (const auto &single_poss_interval : acc_possible_intervals){
        if (single_poss_interval.size() > 0 && single_poss_interval[0].comm_sum >= cur_highest_sum){
            // if there is more than one interval, all of them have the same comm_sum
            if (single_poss_interval[0].comm_sum > cur_highest_sum){
                cur_highest_sum = single_poss_interval[0].comm_sum;
                possible_intervals.clear();
            }

            for (const auto &interval : single_poss_interval){
                possible_intervals.push_back(std::move(interval));
            }
        }
    }

    // return the result converted into python data structures
    return convert_intervals_to_py_repr(possible_intervals);
}

/**
 * Finds the time interval(s) of maximum the given seconds within the given start and end index having the most 
 * overall communication (i.e. requests and responses) as well as at least number_ids communicating initiators in it. 
 * @param p An rvalue to a promise to return the found intervals.
 * @param number_ids The number of initiator IDs that have to exist in the interval(s).
 * @param max_int_time The maximum time period of the interval.
 * @param start_idx The index of the first message to process with respect to the class member 'messages'.
 * @param end_idx The upper index boundary where the search is stopped at (i.e. exclusive index).
 */
void botnet_comm_processor::find_optimal_interval_helper(std::promise<std::vector<comm_interval> > && p, int number_ids, double max_int_time, int start_idx, int end_idx){
    // setup initial variables
    unsigned int idx_low = start_idx, idx_high = start_idx;  // the indices spanning the interval
    unsigned int comm_sum = 0;  // the communication sum of the current interval
    unsigned int cur_highest_sum = 0;  // the highest communication sum seen so far
    double cur_int_time = 0;  // the time of the current interval
    std::deque<unsigned int> init_ids;  // the initiator IDs seen in the current interval in order of appearance
    std::vector<comm_interval> possible_intervals;  // all intervals that have cur_highest_sum of communication and contain enough IDs

    // Iterate over all messages from start to finish and process the info of each message.
    // Similar to a Sliding Window approach.
    while (1){
        if (idx_high < messages.size())
            cur_int_time = messages[idx_high].time - messages[idx_low].time;
 
        // if current interval time exceeds maximum time period or all messages have been processed, 
        // process information of the current interval
        if (greater_than(cur_int_time, max_int_time) || idx_high >= messages.size()){
            std::set<unsigned int> interval_ids;

            for (std::size_t i = 0; i < init_ids.size(); i++) 
                interval_ids.insert(init_ids[i]);

            // if the interval contains enough initiator IDs, add it to possible_intervals
            if (interval_ids.size() >= (unsigned int) number_ids){
                comm_interval interval = {interval_ids, comm_sum, idx_low, idx_high - 1};
                // reset possible intervals if new maximum of communication is found
                if (comm_sum > cur_highest_sum){
                    possible_intervals.clear();
                    possible_intervals.push_back(std::move(interval));
                    cur_highest_sum = comm_sum;
                }
                // append otherwise
                else if (comm_sum == cur_highest_sum)
                    possible_intervals.push_back(std::move(interval));
            }

            // stop if all messages have been processed
            if (idx_high >= messages.size())
                break;
        }

        // let idx_low "catch up" so that the current interval time fits into the maximum time period again
        while (greater_than(cur_int_time, max_int_time)){
            if (idx_low >= (unsigned int) end_idx)
                goto end; 

            abstract_msg &cur_msg = messages[idx_low];
            // if message was not a timeout, delete the first appearance of the initiator ID 
            // of this message from the initiator list and update comm_sum
            if (cur_msg.type != TIMEOUT){
                comm_sum--;
                init_ids.pop_front();
            }

            idx_low++;
            cur_int_time = messages[idx_high].time - messages[idx_low].time;
        }

        // consume the new message at idx_high and process its information
        abstract_msg &cur_msg = messages[idx_high];
        // if message is request, add src to initiator list
        if (msgtype_is_request(cur_msg.type)){
            init_ids.push_back(cur_msg.src);
            comm_sum++;
        }
        // if message is response, add dst to initiator list
        else if (msgtype_is_response(cur_msg.type)){
            init_ids.push_back(cur_msg.dst);
            comm_sum++;
        }

        idx_high++;
    }

    end: p.set_value(possible_intervals);
}

/**
 * Finds the time interval of maximum the given seconds starting at the given index. If it does not have at least number_ids 
 * communicating initiators in it or the index is out of bounds, an empty dict is returned.
 * @param start_idx the starting index of the returned interval
 * @param number_ids The number of initiator IDs that have to exist in the interval.
 * @param max_int_time The maximum time period of the interval.
 * @return A (python) dict (keys: 'IDs', Start', 'End'), which represents an interval with its list of initiator IDs, 
 * a start index and an end index. The indices are with respect to the first abstract message.
 */
py::dict botnet_comm_processor::find_interval_from_startidx(int start_idx, int number_ids, double max_int_time){
    // setup initial variables
    unsigned int cur_idx = start_idx;  // the current iteration index
    double cur_int_time = 0;  // the time of the current interval
    std::deque<unsigned int> init_ids;  // the initiator IDs seen in the current interval in order of appearance
    py::dict comm_interval_py;  // the communication interval that is returned

    if ((unsigned int) start_idx >= messages.size()){
        return comm_interval_py;
    }

    // Iterate over all messages starting at start_idx until the duration or the current index exceeds a boundary
    while (1){
        if (cur_idx < messages.size())
            cur_int_time = messages[cur_idx].time - messages[start_idx].time;
 
        // if current interval time exceeds maximum time period or all messages have been processed, 
        // process information of the current interval
        if (greater_than(cur_int_time, max_int_time) || cur_idx >= messages.size()){
            std::set<unsigned int> interval_ids;

            for (std::size_t i = 0; i < init_ids.size(); i++) 
                interval_ids.insert(init_ids[i]);

            // if the interval contains enough initiator IDs, convert it to python representation and return it
            if (interval_ids.size() >= (unsigned int) number_ids){
                py::list py_ids;
                for (const auto &id : interval_ids){
                    py_ids.append(id);
                }
                comm_interval_py["IDs"] = py_ids;
                comm_interval_py["Start"] = start_idx;
                comm_interval_py["End"] = cur_idx - 1;
                return comm_interval_py;
            }
            else {
                return comm_interval_py;
            }
        }

        // consume the new message at cur_idx and process its information
        abstract_msg &cur_msg = messages[cur_idx];
        // if message is request, add src to initiator list
        if (msgtype_is_request(cur_msg.type))
            init_ids.push_back(cur_msg.src);
        // if message is response, add dst to initiator list
        else if (msgtype_is_response(cur_msg.type))
            init_ids.push_back(cur_msg.dst);

        cur_idx++;
    }
}

/**
 * Finds the time interval of maximum the given seconds ending at the given index. If it does not have at least number_ids 
 * communicating initiators in it or the index is out of bounds, an empty dict is returned.
 * @param end_idx the ending index of the returned interval (inclusive)
 * @param number_ids The number of initiator IDs that have to exist in the interval.
 * @param max_int_time The maximum time period of the interval.
 * @return A (python) dict (keys: 'IDs', Start', 'End'), which represents an interval with its list of initiator IDs, 
 * a start index and an end index. The indices are with respect to the first abstract message.
 */
py::dict botnet_comm_processor::find_interval_from_endidx(int end_idx, int number_ids, double max_int_time){
    // setup initial variables
    int cur_idx = end_idx;  // the current iteration index
    double cur_int_time = 0;  // the time of the current interval
    std::deque<unsigned int> init_ids;  // the initiator IDs seen in the current interval in order of appearance
    py::dict comm_interval_py;  // the communication interval that is returned

    if (end_idx < 0){
        return comm_interval_py;
    }

    // Iterate over all messages starting at end_idx until the duration or the current index exceeds a boundary
    while (1){
        if (cur_idx >= 0)
            cur_int_time = messages[end_idx].time - messages[cur_idx].time;
 
        // if current interval time exceeds maximum time period or all messages have been processed, 
        // process information of the current interval
        if (greater_than(cur_int_time, max_int_time) || cur_idx < 0){
            std::set<unsigned int> interval_ids;

            for (std::size_t i = 0; i < init_ids.size(); i++) 
                interval_ids.insert(init_ids[i]);

            // if the interval contains enough initiator IDs, convert it to python representation and return it
            if (interval_ids.size() >= (unsigned int) number_ids){
                py::list py_ids;
                for (const auto &id : interval_ids){
                    py_ids.append(id);
                }
                comm_interval_py["IDs"] = py_ids;
                comm_interval_py["Start"] = cur_idx + 1;
                comm_interval_py["End"] = end_idx;
                return comm_interval_py;
            }
            else {
                return comm_interval_py;
            }
        }

        // consume the new message at cur_idx and process its information
        abstract_msg &cur_msg = messages[cur_idx];
        // if message is request, add src to initiator list
        if (msgtype_is_request(cur_msg.type))
            init_ids.push_back(cur_msg.src);
        // if message is response, add dst to initiator list
        else if (msgtype_is_response(cur_msg.type))
            init_ids.push_back(cur_msg.dst);

        cur_idx--;
    }
}

/**
 * Finds all initiator IDs contained in the interval spanned by the two indices.
 * @param start_idx The start index of the interval.
 * @param end_idx The last index of the interval (inclusive).
 * @return A (python) list containing all initiator IDs of the interval.
 */
py::list botnet_comm_processor::get_interval_init_ids(int start_idx, int end_idx){
    // setup initial variables
    unsigned int cur_idx = start_idx;  // the current iteration index
    std::set<unsigned int> interval_ids;
    py::list py_ids;  // the communication interval that is returned

    if ((unsigned int) start_idx >= messages.size()){
        return py_ids;
    }

    // Iterate over all messages starting at start_idx until the duration or the current index exceeds a boundary
    while (1){
        // if messages have been processed
        if (cur_idx >= messages.size() || cur_idx > (unsigned int) end_idx){
            for (const auto &id : interval_ids)
                py_ids.append(id);
            return py_ids;
        }

        // consume the new message at cur_idx and process its information
        abstract_msg &cur_msg = messages[cur_idx];
        // if message is request, add src to initiator list
        if (msgtype_is_request(cur_msg.type))
            interval_ids.insert(cur_msg.src);
        // if message is response, add dst to initiator list
        else if (msgtype_is_response(cur_msg.type))
            interval_ids.insert(cur_msg.dst);

        cur_idx++;
    }
}

/**
 * Checks whether the given message type corresponds to a request.
 * @param mtype The message type to check.
 * @return true(1) if the message type is a request, false(0) otherwise.
 */
int botnet_comm_processor::msgtype_is_request(unsigned short mtype){
    return mtype == SALITY_HELLO || mtype == SALITY_NL_REQUEST;
}

/**
 * Checks whether the given message type corresponds to a response.
 * @param mtype The message type to check.
 * @return true(1) if the message type is a response, false(0) otherwise.
 */
int botnet_comm_processor::msgtype_is_response(unsigned short mtype){
    return mtype == SALITY_HELLO_REPLY || mtype == SALITY_NL_REPLY;
}

/**
 * Converts the given vector of communication intervals to a python representation 
 * using (python) lists and (python) tuples.
 * @param intervals The communication intervals to convert.
 * @return A boost::python::list containing the same interval information using boost::python::dict for each interval.
 */
py::list botnet_comm_processor::convert_intervals_to_py_repr(const std::vector<comm_interval> &intervals){
    py::list py_intervals;
    for (const auto &interval : intervals){
        py::list py_ids;
        for (const auto &id : interval.ids){
            py_ids.append(id);
        }
        py::dict py_interval;
        py_interval["IDs"] = py_ids;
        py_interval["Start"] = interval.start_idx;
        py_interval["End"] = interval.end_idx;
        py_intervals.append(py_interval);
    }
    return py_intervals;
}

// void botnet_comm_processor::print_message(const abstract_msg &message){
//     std::cout << "Src: " << message.src << "   Dst: " << message.dst << "   Type: " << message.type << "   Time: " << message.time << "   LineNumber: " << message.line_no << std::endl;
// }

PYBIND11_MODULE (libbotnetcomm, m) {
    py::class_<botnet_comm_processor>(m, "botnet_comm_processor")
            .def(py::init<py::list>())
            .def(py::init<>())
            .def("find_interval_from_startidx", &botnet_comm_processor::find_interval_from_startidx)
            .def("find_interval_from_endidx", &botnet_comm_processor::find_interval_from_endidx)
            .def("find_optimal_interval", &botnet_comm_processor::find_optimal_interval)
            .def("get_interval_init_ids", &botnet_comm_processor::get_interval_init_ids)
            .def("get_messages", &botnet_comm_processor::get_messages)
            .def("get_message_count", &botnet_comm_processor::get_message_count)
            .def("parse_csv", &botnet_comm_processor::parse_csv)
            .def("parse_xml", &botnet_comm_processor::parse_xml)
            .def("set_messages", &botnet_comm_processor::set_messages)
            .def("write_xml", &botnet_comm_processor::write_xml);
}
