# ID2T - Intrusion Detection Dataset Toolkit
A toolkit for synthetic injection of attacks into network datasets.

## Synopsis
As Intrusion Detection Systems encounter growing importance in the area of network security, the need of high quality network datasets for evaluation against real-world attacks rises. 

Comparability of the results must be ensured by use of publicly available datasets. Existing datasets, however, suffer from several disadvantages. Often they do not provide ground trouth, consist of outdated traffic and do not contain any payload because of privacy reasons. Moreover, frequently datasets do not contain latest attacks and missing attack labels make it difficult to identify existing attacks and enable a transparent comparison of Intrusion Detection Systems.

The ID2T application was first proposed in [[1]](#references) and targets the injection of attacks into existing network datasets. At first, it analyzes a given dataset and collects statistics from it. These statistics are stored into a local database. Next, these statistics can be used to define attack parameters for the injection of one or multiple attacks. Finally, the application creates the required attack packets and injects them into the existing file. Resulting in a new PCAP with the injected attacks and a label file indicating the position of the attack in the dataset.

### References
[1] [Cordero, Vasilomanolakis, Milanov et al.: ID2T: a DIY Dataset Creation Toolkit for Intrusion Detection System](https://www.tk.informatik.tu-darmstadt.de/fileadmin/user_upload/Group_TK/filesDownload/Published_Papers/id2t.pdf)

## Getting Started

### Prerequisities
ID2T is written for Python 3.4 and C++ 11. The main modules were developed in Python whereas the statistics collection and PCAP merging is performed, due to performance reasons, by a C++ module which uses the library [Libtins](https://github.com/mfontanini/libtins/). These modules are invoked in python by using [Boost.Python](http://www.boost.org/doc/libs/1_62_0/libs/python/doc/html/index.html).

#### Required Python Packages
The following non-standard packages are required to run ID2T. Missing packages can be installed from terminal via  `` sudo pip install <packagename> ``.

* ``scapy-python3``: used for packet creation
* ``lea``: used for calculation of parameters derived by the gathered statistics

### Installation
There is no installation required. Simply clone the repository to get started:

`` git clone https://git.tk.informatik.tu-darmstadt.de/SPIN/ID2T-toolkit ``

After making the main file executable `` sudo chmod +x CLI.py ``, the application can be started by `` .\CLI.py ``

## Usage examples 
In this section we provide some examples on how to use ID2T.

### Injecting an attack into an existing dataset
In the following we inject the _PortscanAttack_ into the dataset *pcap_capture.pcap*:

`` .\CLI.py -i /home/user/pcap_capture.pcap -a PortscanAttack ip.src=10.192.168.178.2 mac.src=32-08-24-DC-8D-27 inject.at-timestamp=1476301843 ``

__Explanation__: The parameter ``-i/--input`` takes the path to the PCAP file. This triggers the statistics calculation of the file. After the calculation, the statistics are stored into a SQLite database. If the statistics were already computed in an earlier run, the data is retrieved from the generated database. This saves time as the calculation of the statistics may take long time - depending on the PCAP file size.

An attack can be injected by providing ``-a/--attack`` followed by the attack name and the attack parameters. The available attacks and the allowed attack parameters vary, see the attack-specific wiki articles for a reference of supported attack parameters. The parameter  ``-a/--attack`` can be provided multiple times for injection of multiple attacks. In this case the attacks are injected sequentially.

After injecting the attack, the application generates a XML label file containing the timestamps of the first and last attack packet. The file name is equal to the output file, except with ``_labels.xml`` as suffix. 
The toolkit recognizes if the input dataset has an associated label file. This requires a file naming according to the aforementioned scheme, e.g., mydataset.pcap and mydataset_labels.xml. In this case ID2T parses the label file and the resulting output label file contains the labels from the input label file plus the labels from the recently added attack(s).

### Querying the statistics database
The statistics database supports queries of two different types:
- standard SQL queries, called _user-defined query_, which are passed directly to the SQLite database,  
e.g. `` SELECT ipAddress from ip_statistics WHERE pktsSent>1000 ``
- pre-defined queries, called _named query_, which are like shortcuts for SQL queries,  
e.g. ``most_used(ipAddress)``, ``random(all(ipAddress))``  
The named queries can further be divided into two classes: 
	- _selectors_ gather information from the database; the result can be a list of values, like ``all(ipAddress)``
	- _extractors_ can be applied on gathered data and always reduce the result set to a single element, e.g. ``random(...)`` returns a randomly chosen element of the list

A complete list of supported named queries can be found in section [Named Queries](#named-queries). The database scheme, required for building SQL queries, is documented in the wiki article [DB Tables and Fields](/wiki/Statistics-DB%3A-Tables)

These two types of queries can be executed either by providing the query string as an application argument or by going into the query mode. The application argument ``-q/--query`` takes a user-defined query or named query as input and prints the results to the terminal:

Execute query directly: 
`` .\CLI.py -i /home/user/pcap_capture.pcap -q <query> ``  

If  ``-q/--query`` is called without any argument, the application enters into the query mode. This mode is like a read-eval-print-loop (REPL) for SQL queries. In this mode the user can repetively provide a query (must end by ";"), send the query by pressing ENTER and see the response in the terminal:

Go into query mode: `` .\CLI.py -i /home/user/pcap_capture.pcap -q ``  

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
By calling ``.\CLI.py -h``, a list of available application arguments with a short description is printed on screen. The arguments are described more detailed in the wiki article [Program Arguments](/wiki/Program-Arguments).

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

__Extractors__ are to be used on the result of a named query. If the result is a list, applying an extractor reduces the result set to a single element. If the result is already a single element, the extractor is ignored.
```
random(...)  -> returns a random element from a list
first(...)   -> returns the first element from a list
last(...)    -> returns the last element from a list
```
Attention: Named queries are designed to be combined with extractors, like ``random(all(ipAddress))``. But it is currently NOT possible to encapsulate multiple named queries, like `` macAddress(ipAddress=most_used(ipAddress))``. This can be circumvented by first querying ``most_used(ipAddress)`` and then inserting the result as argument in ``macAddress(…)``. 

## Versioning
The [SemVer](http://semver.org/spec/v2.0.0.html) is used for versioning. For currently available versions of ID2T, see page [releases](https://git.tk.informatik.tu-darmstadt.de/SPIN/ID2T-toolkit/releases).

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
