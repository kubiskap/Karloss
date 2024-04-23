# Karloss_v2

## Introduction
This Python script is created as partt of my bachelor thesis. It will be used as a tool in the process of verifying C-ITS hardware developed by various manufacturers, whether the C-ITS messages meet the standard or not.

### Requirements:
* Python version >3.10,
* tshark installed,
* Python packages:
  * `asn1tools`, `pyshark`, `jsonpath_ng`, `tk` (GUI), `folium` (map)

## How it works
The data input into the software is a set of packets captured and stored in a `.pcap` file.

`Pyshark`, a package integrating Wireshark into Python, is used to get the raw encoded data. The `asn1tools` package is used to decode the raw data using ASN.1 files, whose location is specified in `config.json` for each type of message configured.

Additionally, the `asn1tools` package is used to compile the ASN.1 files into a dictionary. A custom recursive function is used to rebuild this dictionary data into a nested dictionary that resembles the structure of each C-ITS data packet.

Using a generator, each parameter of each packet is evaluated based on its' type specified in the ASN.1 specification. The state of each parameter can be:
* OK -- the parameter is entirely complicit with the specification,
* Warning -- there are some minor discrepancies with the specification, or
* Error -- the value parameter is completely wrong and does not comply with the specification.
For every parameter, there is a specified description of the reason why the parameter was evaluateed as such. Based on the "worst" parameter, the entire packet is evaluated.

The user will be prompted to enter the directory, in which he wishes to save the output. The output is then stored in a directory named `session_DD-MM-YYYY-HH-MM-SS` and contains the following:
* directory `packets`, containing each analysed packet in the session:
  * packet type,
  * packet state (OK, Warning, Error),
  * problematic parameters with problem descriptions,
  * analysed data -- preserved packet structure with each parameter containing value, parameter state and parameter problems,
* `pkt_types.json`, containing information about counts of each packet types in the file and
* `summary.json`, containing information about counts of each parameter being OK, Warning or Error

## Usage
Clone the root directory of the repository. Check if all required software in __Requirements__ is installed. The packages with parentheses behind them are not required for the basic CLI functionality, but the features specified in parentheses will NOT work.

### CLI
Currently, the script is not yet structured as a Python package, so you need to start by importing `PacketAnalyser` class from the `core.py` script.

To be able to do that, you need to extend your Python PATH with the directory you cloned the repository into.
```
import sys
sys.path.extend(['C:\\PATH\\TO\\ROOT\\DIRECTORY'])
```

Now you should be able to import the main script:
```
from core import PacketAnalyser
```

To start a new session of the script, create a class object of `PacketAnalyser`:
```
karloss = PacketAnalyser(config_location='PATH\\TO\\CONFIG.JSON')
```
If you don't want to specify your custom config location and want to use the file included in the root of the script, just call `karloss = PacketAnalyser()`.

To import the pcap file, call method `import_file()` of the object:
```
karloss.import_file(input_file='PATH\\TO\\PCAP\\FILE')
```

Finally, call the `analyse()` method to launch the analysis:
```
karloss.analyse()
```

To output the results of a successful analysis, call the `output_results()` method:
```
karloss.output_results(output_location='PATH\\TO\\OUTPUT\\DIRECTORY')
```

The core script enables logging each session into the `log` directory in the script root. Cache is also implemented, meaning that for repeated analysis of the same file, packets are imported from cache. If the analysis were to be interrupted, the script should pick up where it left off after launching the analysis again for the same file.

### GUI
The usage of the GUI is fairly straightforward, but some features are not yet implemented. You should be able to just launch the `gui.py` file using console:
```
python C:\\PATH\\TO\\SCRIPT\\ROOT\\gui.py
```

In the first window, you will be prompted to select the `config.json` file and the pcap file. After clicking `Accept Config`, a window with a text box will pop up. In this textbox, all of the output of CLI is provided. Click the `Analyse` button to start analysis. After completion, you can click the `Output Results` button and select the output directory.
