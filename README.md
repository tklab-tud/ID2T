[![Build Status](https://travis-ci.org/tklab-tud/ID2T.svg?branch=master)](https://travis-ci.org/tklab-tud/ID2T)

<p align="center">
<img src="https://git.tk.informatik.tu-darmstadt.de/SPIN/ID2T-toolkit/raw/master/logo/id2t.png"></p>

# ID2T - Intrusion Detection Dataset Toolkit
A toolkit for injecting synthetic attacks into PCAP files.

## Synopsis
As Intrusion Detection Systems encounter growing importance in the area of network security, the need of high quality network datasets for evaluation against real-world attacks rises.

Comparability of the results must be ensured by use of publicly available datasets. Existing datasets, however, suffer from several disadvantages. Often they do not provide ground truth knowledge, consist of outdated traffic and do not contain any payload because of privacy reasons. Moreover, frequently datasets do not contain latest attacks and missing attack labels make it difficult to identify existing attacks and enable a transparent comparison of Intrusion Detection Systems.

The ID2T toolkit was first proposed in [[1]](#references) and [[2]](#references) and targets the injection of attacks into existing network datasets. At first, it analyzes a given dataset and collects statistics from it. These statistics are stored into a local database. Next, these statistics can be used to define attack parameters for the injection of one or multiple attacks. Finally, the application creates the required attack packets and injects them into the existing file. Resulting in a new PCAP with the injected attacks and a label file indicating the position (timestamps) of the first and last attack packet.

ID2T was also presented in Blackhat Europe 2017 as part of the Arsenal session (https://www.blackhat.com/eu-17/arsenal/schedule/index.html).

### References
[1] [Garcia Cordero et al. (2015) ID2T: a DIY Dataset Creation Toolkit for Intrusion Detection System](https://www.tk.informatik.tu-darmstadt.de/fileadmin/user_upload/Group_TK/filesDownload/Published_Papers/id2t.pdf)

[2] [Vasilomanolakis et al. (2016) Towards the creation of synthetic, yet realistic, intrusion detection datasets](https://www.tk.informatik.tu-darmstadt.de/fileadmin/user_upload/Group_TK/filesDownload/Published_Papers/id2t-f.pdf)

## Getting Started

### Compilation and Installation
Clone the repository to get started with the installation:
``git clone https://github.com/tklab-tud/ID2T``

Install dependencies, initialize submodules, build the C++ modules and create the ID2T executables:
``./build.sh``\
If you encounter any issues please refer to our [Dependencies wiki page](https://github.com/tklab-tud/ID2T/wiki/Dependencies).

To skip dependency installation use the ``--non-interactive`` argument:
``./build.sh --non-interactive``

Run ID2T with the command ``./id2t``.

Run unit tests with the command ``./run_tests``.

Run efficiency tests with the command ``./test_efficiency``.

## Usage examples
In this section, we provide examples on how ID2T is used.

### Injecting an attack into an existing dataset
In the following we inject the _PortscanAttack_ into the dataset *pcap_capture.pcap*:

`` ./id2t -i /home/user/pcap_capture.pcap -a PortscanAttack ip.src=192.168.178.2 mac.src=32:08:24:DC:8D:27 inject.at-timestamp=1476301843 ``

__Explanation__: The parameter ``-i/--input`` takes the path to the PCAP file. This triggers the statistics calculation of the file. After the calculation, the statistics are stored into a SQLite database. If the statistics were already computed in an earlier run, the data is retrieved from the generated database. This saves time as the calculation of the statistics may take long time - depending on the PCAP file size.

An attack can be injected by providing ``-a/--attack`` followed by the attack name and the attack parameters. The available attacks and the allowed attack parameters vary, see the attack-specific wiki articles for a reference of supported attack parameters. The parameter  ``-a/--attack`` can be provided multiple times for injection of multiple attacks. In this case the attacks are injected sequentially.

After injecting the attack, the application generates a XML label file containing the timestamps of the first and last attack packet. The file name is equal to the output file, except with ``_labels.xml`` as suffix.
The toolkit recognizes if the input dataset has an associated label file. This requires a file naming according to the aforementioned scheme, e.g., mydataset.pcap and mydataset_labels.xml. In this case ID2T parses the label file and the resulting output label file contains the labels from the input label file plus the labels from the recently added attack(s).

### The Statistics database
Whenever ID2T processes a pcap file, it creates a database detailing many things related to the network traffic it has processed. These details can be seen using the _query mode_ of ID2T. To specify a query against a pcap file, use the option ``-q/--query`. For example, if we want to know the IP address with the most activity in the pcap file 'test.pcap' we can issue the command:
    ./id2t -i test.pcap -q 'most_used(ipAddress);'

The _query mode_ serves as a place where standard SQL queries (known as _user-defined queries_) can be issued against the database created for a pcap file. Furthermore, the most commonly used queries are provided with special keywords known as _named queries_.

- A _user-defined query_ looks like this:
  - e.g. `` SELECT ipAddress FROM ip_statistics WHERE pktsSent > 1000 ``
- A pre-defined query, known as _named query_, looks like this:
  - e.g. ``most_used(ipAddress)``, ``random(all(ipAddress))``

The _named queries_ can be further divided into two classes:
- _selectors_ - gather information from the database; the result can be a list of values
  - e.g. ``all(ipAddress)``
- _extractors_ - can be applied on gathered data and always reduce the result set to a single element
  - e.g. ``random(...)`` returns a randomly chosen element of the list

A complete list of supported named queries can be found in section [Named Queries](#named-queries). The database scheme, required for building SQL queries, is documented in the wiki article [DB Tables and Fields](https://github.com/tklab-tud/ID2T/wiki/ID2Tv1.0-Statistics-DB:-Tables)

If  ``-q/--query`` is called without an argument, the application enters into REPL query mode. This mode is like a standard read-eval-print-loop (REPL) for SQL queries. In this mode, the user can repeatedly input queries (each query must finish with a ";" (semicolon)); send the query by pressing ENTER and see the response in the terminal:

Example query mode usage: ``./id2t -i test.pcap -q``

_Example output_:

	Input file: /home/user/pcap_capture.pcap
	Located statistics database at: /home/pjattke/ID2T_data/db/99/137/81a0a71b0f36.sqlite3
	Loaded file statistics in 0.00 sec from statistics database.
	Entering into query mode...
	Enter statement ending by ';' and press ENTER to send query. Exit by sending an empty query..
	most_used(ipAddress);
	Query 'most_used(ipAddress);' returned:
	203.114.236.243
	avg(ttlValue);
	Query 'avg(pktsSent);' returned:
	5.322

## Command reference

### Application Arguments
By calling ``./id2t -h``, a list of available application arguments with a short description is shown.


### Statistics DB Queries

#### Named Queries

___Selectors___ are named queries which return a single element or a list of elements, depending on the values in the database and the query.

For example, the named query `` most_used(ipAddress) `` may return a single IP address if the most used IP address, based on the sum of packets sent and received, is unique. If there are multiple IP addresses with the same number of packets sent plus packets received, a list of IP addresses is returned. As the user cannot know how many values are returned, the extractors are ignored if the result is a single element.

	most_used(ipAddress | macAddress | portNumber | protocolName | ttlValue)

	least_used(ipAddress | macAddress | portNumber | protocolName | ttlValue)

	avg(pktsReceived | pktsSent | kbytesSent | kbytesReceived | ttlValue | mss)

	all(ipAddress | ttlValue | mss | macAddress | portNumber | protocolName)

There are also parameterizable selectors which take conditions as input. Following two examples to show the syntax by example:

	ipAddress(macAddress=AA:BB:CC:DD:EE:FF, pktsSent > 1000, kbytesReceived < 1000)
	-> returns one or multiple IP addresses matching the given criterias
	Supports the fields: macAddress, ttlValue, ttlCount, portName, portNumber, portDirection, kbytesSent, kbytesReceived, pktsSent, pktsReceived,

	macAddress(ipAddress=192.168.178.2)
	-> returns the MAC address matching the given criteria
	Supports the field: ipAddress

Parameterizable selectors also allow for specifying another query in the condition instead of a specific value, like the following example demonstrates:
	macAddress(ipAddress in most_used(ipAddress))

Conditions inside parameterizable selectors can contain all the usual comparison operators (<, <=, =, >=, >) when the right side of the condition is a single value. If the right side is a list, such as the return value of e.g. most_used(), the `` in ``-operator is to be used instead, unless the list is reduced to a single value by the use of an extractor.

The following examples provide a demonstration of how lists can be used inside parameterizable selectors:
```
macAddress(ipAddress in ipAddress(pktssent > 1))         -> Returns the MAC addresses of all IP addresses that sent more than one packet
macAddress(ipAddress = random(ipAddress(pktssent > 1)))  -> Returns the MAC address of a random IP address out of all IP addresses that sent more than one packet
macAddress(ipAddress in [192.168.189.1,192.168.189.143]) -> Returns the MAC address of all IP addresses in the provided list
```

__Extractors__ are to be used on the result of a named query. If the result is a list, applying an extractor reduces the result set to a single element. If the result is already a single element, the extractor is ignored.
```
random(...)  -> returns a random element from a list
first(...)   -> returns the first element from a list
last(...)    -> returns the last element from a list
```
Named queries are designed to be combined with extractors, like ``random(all(ipAddress))``

## Contributors

For information on Contributors and how to contribute see our [Contributors file](./CONTRIBUTORS.md).

## Versioning
The [SemVer](http://semver.org/spec/v2.0.0.html) is used for versioning. For currently available versions of ID2T, see page [releases](https://github.com/tklab-tud/ID2T/releases).

## Release History

* 0.1.0: Initial release
	* Added attack: Portscan Attack

## License

Distributed under the MIT license. See [LICENSE](LICENSE.md) for more information.

