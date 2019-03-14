
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


### Inject Configuration

Packet injection is configured using a YAML configuration file specified by `custom.payload.file=` argument. A default example of inject configuration file can be found in [./resources/mix_config.yml](resources/mix_config.yml). Copy the configuration file and update all required options according to your inject scenario.

#### Configuration Options

The following list introduces all available configuration options together with their brief explanation:

* **atk.file** (mandatory): Path to the annotated unit trace file. Option *default* will inject [./resources/hydra-1_tasks.pcap](resources/hydra-1_tasks.pcap) packet trace.
```yaml
atk.file: default
```

* **read.write** (mandatory): Specify an approach of packets processing. Use *sequence* for processing packets one by one (consumes less memory), or *bulk* for processing packets all at once.
```yaml
read.write: sequence
```

* **timestamp** (mandatory): Specification of functions used for timestamp adaptation. The following list contains all available options:
  * **generation** – *default*, *timestamp_shift*, *tcp_avg_shift*, *timestamp_dynamic_shift*;
  * **postprocess** – *timestamp_delay*, *timestamp_delay_forIPlist*, *timestamp_delay_forIPconst*, *timestamp_random_oscillation* (postprocess functions are applied in specified order);
  * **generation.alt** – *default*, *timestamp_shift*, *timestamp_dynamic_shift*;
  * **random.threshold** – float value (used by postprocessesing functions *timestamp_random_oscillation*, *timestamp_delay_forIPconst*, *timestamp_delay*).
```yaml
timestamp:
  generation: tcp_avg_shift
  postprocess: 
    - function: timestamp_delay_forIPlist
  generation.alt: timestamp_dynamic_shift
  random.treshold: 0.001
```

* **ip.map**: Mapping of IP addresses in the annotated unit to addresses in the target trace file. No additional adaptation of annotated unit is performed if selected IPs are not presented in the target trace file.
```yaml
ip.map:
  - ip:
      old: 240.0.0.2
      new: 192.168.0.11
```

* **mac.map**: Mapping of MAC addresses in the annotated unit to addresses in the target trace file.
```yaml
mac.map:
  - mac: 
      old: 08:00:27:bd:c2:37
      new: 00:11:09:95:26:FE
```

* **port.ip.map**: Changing ports used in the annotated unit into a new port. Option *type* in *ip* determines if the defined address is old or newer one after IPs mapping (available options are *old* or *new*).
```yaml
port.ip.map:
  - ip:
      type: old 
      address: 240.0.0.2
    port: 
      old: 22
      new: 2222
```


## Contribution

Pull requests to our fork as well as to official ID2T repository are welcome! For major changes, please open an issue first to discuss what you would like to change.

*If you are interested in research collaborations, don't hesitate to contact us at  [https://csirt.muni.cz](https://csirt.muni.cz/about-us/contact?lang=en)!*
