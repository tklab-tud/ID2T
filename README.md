
# Trace-Share: ID2T

Fork of the official **[ID2T repository](https://github.com/tklab-tud/ID2T)** extended by functions to modify and combine existing packet traces.

[![Build Status](https://travis-ci.org/Trace-Share/ID2T.svg?branch=master)](https://travis-ci.org/Trace-Share/ID2T)


## Requirements

We are trying to avoid adding any additional requirements to maintain backward compatibility with the official repository. All information about ID2T dependencies and required libraries are available at official project Readme (see section [Getting Started](https://github.com/tklab-tud/ID2T#getting-started)).


## Installation

Installation steps are similar to the official repository (see section [Compilation and Installation](https://github.com/tklab-tud/ID2T#compilation-and-installation)). The following list provides basic installation and build commands only. For a more detailed guide see the official repository.

* `$ ./build.sh` – install dependencies, initialize submodules, build the C++ modules and create ID2T executables
* `$ ./id2t -h` – show ID2T usage and check if everything is correctly installed


## Usage

ID2T is an awesome tool with lots of interesting functionality for the creation of network traffic datasets. You can use it for injection of **simulated attack** into the existing network traffic data or get **detailed statistics** about existing data. Check out the [Usage examples](https://github.com/tklab-tud/ID2T#usage-examples) section of the official repository to get more information about ID2T capabilities.

The following sections present extended ID2T functionality with a focus on **modification and insertion of existing packet traces**. The goal of this functionality is to modify shared annotated units of network traffic instead of their artificial generation.

### Inject Configuration



### Basic Commands

Use the following command to start injection of an annotated unit into the target trace file using properties specified in the configuration. The command produces *&lt;output&gt;.pcap* containing result mix and *&lt;output&gt;_labels.xml* with mix information. If you want to get only annotated unit modified by statistics from target file, append argument `-ie`.

```bash
$ ./id2t -i <target_file> -a Mix custom.payload.file=<configuration> inject.at-timestamp=<timestamp> -o <output>
```

The following example shows a combination of SSH attack with the testing packet trace using default configuration available in this repository.

```bash
$ ./id2t -i ./resources/test/reference_1998.pcap -a Mix custom.payload.file=./resources/mix_config.yml \
inject.at-timestamp=500 -o ./mixed
```


## Contribution

Pull requests to our fork as well as to official ID2T repository are welcome! For major changes, please open an issue first to discuss what you would like to change.

*If you are interested in research collaborations, don't hesitate to contact us at  [https://csirt.muni.cz](https://csirt.muni.cz/about-us/contact?lang=en)!*
