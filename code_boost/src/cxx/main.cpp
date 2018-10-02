#include "pcap_processor.h"
#include <pybind11/pybind11.h>
#include <pybind11/embed.h>

namespace py = pybind11;

int main(int argc, char *argv[]){
    if (argc > 4) {
        // get user arguments
        std::string pcap_path = argv[1];
        std::string extra_tests = argv[2];
        std::string resource_path = argv[3];
        std::string db_path = argv[4];
        py::float_ elem = *reinterpret_cast<double*>(argv[5]);

        // init other needed vars
        py::scoped_interpreter guard{};
        bool del = true;
        py::list intervals;
        intervals.append(elem);

        // execute pcap processor
        pcap_processor pp(pcap_path, extra_tests, resource_path, db_path);
        pp.collect_statistics(intervals);
        pp.write_to_database(db_path, intervals, del);

        return 0;
    } else {
        // display error and example execution
        std::cerr << "Error with argument parsing." << std::endl;
        std::cerr <<  "example execution inside ID2T-toolkit dir (all arg paths should be absolute):" << std::endl;
        std::cerr <<  "$ code_boost/src/build/main <path_to_pcap_file> <extra_tests> <path_to_id2t_resource_dir> <path_to_db_file> <interval_length>" << std::endl;
    }
}
