# ID2T - Intrusion Detection Dataset Toolkit
A toolkit for injecting synthetic attacks into PCAP files.

## Synopsis
As Intrusion Detection Systems encounter growing importance in the area of network security, the need of high quality network datasets for evaluation against real-world attacks rises.

Comparability of the results must be ensured by use of publicly available datasets. Existing datasets, however, suffer from several disadvantages. Often they do not provide ground trouth, consist of outdated traffic and do not contain any payload because of privacy reasons. Moreover, frequently datasets do not contain latest attacks and missing attack labels make it difficult to identify existing attacks and enable a transparent comparison of Intrusion Detection Systems.

The ID2T application was first proposed in [[1]](#references) and targets the injection of attacks into existing network datasets. At first, it analyzes a given dataset and collects statistics from it. These statistics are stored into a local database. Next, these statistics can be used to define attack parameters for the injection of one or multiple attacks. Finally, the application creates the required attack packets and injects them into the existing file. Resulting in a new PCAP with the injected attacks and a label file indicating the position (timestamps) of the first and last attack packet.

### References
[1] [Cordero, Vasilomanolakis, Milanov et al.: ID2T: a DIY Dataset Creation Toolkit for Intrusion Detection System](https://www.tk.informatik.tu-darmstadt.de/fileadmin/user_upload/Group_TK/filesDownload/Published_Papers/id2t.pdf)

## Getting Started

### Prerequisities
ID2T is written using Python 3.4 and C++ 11. The main logic is programmed in Python whereas performance critical components are programmed in C++11. The C++11 module uses the library [Libtins](https://github.com/mfontanini/libtins/). The python and c++ modules interact with each other through the library [Boost.Python](http://www.boost.org/doc/libs/1_62_0/libs/python/doc/html/index.html).

#### Required Python Packages
The following packages are required to run ID2T. Missing packages can be installed from terminal via  `` sudo pip install <packagename> ``.

* ``scapy``: used for packet creation (make sure its the python3 version)
* ``lea``: used for calculation of parameters derived by the gathered statistics

### Installation
Simply clone the repository to get started:

``git clone https://git.tk.informatik.tu-darmstadt.de/SPIN/ID2T-toolkit ``

After cloning the repository, initialize its submodules with
    git submodules init
    git submodules update

Compile the C++ modules (description pending).

Run ID2T with the command ``python ./code/CLI.py`` .

## Usage examples
In this section, we provide some examples on using ID2T.

### Injecting an attack into an existing dataset
In the following we inject the _PortscanAttack_ into the dataset *pcap_capture.pcap*:

`` ./CLI.py -i /home/user/pcap_capture.pcap -a PortscanAttack ip.src=10.192.168.178.2 mac.src=32-08-24-DC-8D-27 inject.at-timestamp=1476301843 ``

__Explanation__: The parameter ``-i/--input`` takes the path to the PCAP file. This triggers the statistics calculation of the file. After the calculation, the statistics are stored into a SQLite database. If the statistics were already computed in an earlier run, the data is retrieved from the generated database. This saves time as the calculation of the statistics may take long time - depending on the PCAP file size.

An attack can be injected by providing ``-a/--attack`` followed by the attack name and the attack parameters. The available attacks and the allowed attack parameters vary, see section [Attack Parameters](#attack-parameters) for details. The parameter  ``-a/--attack`` can be provided multiple times for injection of multiple attacks. In this case the attacks are injected sequentially.

### The Statistics database
Whenever ID2T processes a pcap file, it creates a database detailing many things related to the network traffic it has processed. These details can be seen using the _query mode_ of ID2T. To specify a query against a pcap file, use the option ``-q/--query`. For example, if we want to know the IP address with the most activity in the pcap file 'test.pcap' we can issue the command:
    ./CLI.py -i test.pcap -q most_used(ipAddress)

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

A complete list of supported named queries can be found in section [Named Queries](#named-queries).

If  ``-q/--query`` is called without an argument, the application enters into REPL query mode. This mode is like a standard read-eval-print-loop (REPL) for SQL queries. In this mode, the user can repeatedly input queries (each query must finish with a ";" (semicolon)); send the query by pressing ENTER and see the response in the terminal:

Example query mode usage: ``./CLI.py -i test.pcap -q``

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
By calling ``./CLI.py -h``, a list of available application arguments with a short description is shown.


### Attack Parameters
In this section the allowed attack parameter for all available attacks are presented.

#### Portscan Attack
The _PortscanAttack_ currently supports the following attack parameters:

| Field name          | Description                                                                    | Notes                                                                       |
|---------------------|--------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| mac.src             | MAC address of the attacker                                                    |                                                                             |
| mac.dst             | MAC address of the victim                                                      |                                                                             |
| ip.src              | IP address of the attacker                                                     |                                                                             |
| ip.src.shuffle      | Randomizes the source IP address if port.src is a list of ports                |                                                                             |
| ip.dst              | IP address of the attacker                                                     |                                                                             |
| port.src            | Ports used by the attacker                                                     | Can be specified in different ways, e.g.: "22, 23, 24, 8080", "22-24, 8080" |
| port.src.shuffle    | Randomizes the source ports if port.src is a list of ports                     |                                                                             |
| port.dst            | Ports to be scanned                                                            | Can be specified in different ways, e.g.: "22, 23, 24, 8080", "22-24, 8080" |
| port.dst.shuffle    | Randomizes the destination ports if port.dst is a list of ports                |                                                                             |
| port.open           | Open ports at the victim's side                                                | Can be specified in different ways, e.g.: "22, 23, 24, 8080", "22-24, 8080" |
| port.dst.order-desc | Changes the destination port order from ascending (False) to descending (True) |                                                                             |
| inject.at-timestamp | Starts injecting the attack at the given unix timestamp                        |                                                                             |
| inject.after-pkt    | Starts injecting the attack after the given packet number                      |                                                                             |
| packets.per-second  | Number of packets sent per second by the attacker                              |                                                                             |


### Statistics DB Queries

#### SQL Queries
Querying the SQLite database by standard SQL queries requires knowledge about the database scheme. Therefore we provide a short overview about the tables and fields:

Table: __ip_statistics__


| Field name     | Description                                       |
|----------------|---------------------------------------------------|
| ipAddress      | IP Address of the host these statistics belong to |
| kybtesSent     | KBytes of data sent                               |
| kybtesReceived | KBytes of data received                           |
| pktsSent       | Number of packets sent                            |
| pktsReceived   | Number of packets received                        |

Table: __ip_ttl__

| Field name | Description                            |
|------------|----------------------------------------|
| ipAddress  | IP Address of the host                 |
| ttlValue   | TTL value                              |
| ttlCount   | Number of packets using this TTL value |


Table: __ip_mac__

| Field name | Description             |
|------------|-------------------------|
| ipAddress  | IP Address of the host  |
| macAddress | MAC Address of the host |

Table: __ip_ports__

| Field name    | Description                                                                   |
|---------------|-------------------------------------------------------------------------------|
| ipAddress     | IP Address of the host                                                        |
| portDirection | If data was received on this port "in", if data was sent from this port "out" |
| portNumber    | Port number                                                                   |
| portCount     | Number of packets using this port                                             |

Table: __ip_protocols__

| Field name    | Description                               |
|---------------|-------------------------------------------|
| ipAddress     | IP Address of the host                    |
| protocolName  | Name of the protocol, e.g. TCP, UDP, IPv4 |
| protocolCount | Number of packets using this protocol     |

Table: __tcp_mss__

| Field name | Description                                        |
|------------|----------------------------------------------------|
| ipAddress  | IP Address of the host                             |
| mss        | Maximum Segment Size (TCP option) used by the host |


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

__Extractors__ are to be used on the result of a named query. If the result is a list, applying an extractor reduces the result set to a single element. If the result is already a single element, the extractor is ignored.
```
random(...)  -> returns a random element from a list
first(...)   -> returns the first element from a list
last(...)    -> returns the last element from a list
```
Attention: Named queries are designed to be combined with extractors, like ``random(all(ipAddress))``. But it is currently NOT possible to encapsulate multiple named queries, like `` macAddress(ipAddress=most_used(ipAddress))``. This can be circumvented by first querying ``most_used(ipAddress)`` and then inserting the result as argument in ``macAddress(…)``.

## Versioning
The [SemVer](http://semver.org/spec/v2.0.0.html) is used for versioning. For currently available versions of ID2T, see page [releases](https://git.tk.informatik.tu-darmstadt.de/emmanouil.vasilomano/ID2T-toolkit/releases).

## Release History

* 0.1.0: Initial release
	* Added attack: Portscan Attack


## Authors

- __Emmanouil Vasilomanolakis__ - _contact person, idea of ID2T, guidance and suggestions during development_

- __Carlos Garcia__ - _idea of ID2T, guidance and suggestions during development_

- __Nikolay Milanov__ - _development of first prototype within his Master Thesis_

- __Patrick Jattke__ - _development of first public release within his Bachelor Thesis_

## License

Distributed under the MIT license. See [LICENSE](LICENSE.md) for more information.
