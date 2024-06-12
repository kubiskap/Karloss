# Karloss_v2

## Introduction
This Python script is created as part of my bachelor thesis. It will be used as a tool in the process of verifying C-ITS hardware developed by various manufacturers, whether the C-ITS messages meet the standard or not.

### Requirements:
* Python version ≥3.10,
* tshark (Wireshark) installation,
* Python packages:
  * `asn1tools`, `pyshark`, `jsonpath_ng`, `tk` (GUI), `folium` (map)

## How it works
The data input into the software is a set of packets captured and stored in a `.pcap` file.

`Pyshark`, a package integrating Wireshark into Python, is used to extract the raw encoded data. The `asn1tools` package is used to decode the raw data using ASN.1 files, whose location is specified in `config.json` for each type of message configured.

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
  * analysed parameters -- each parameter containing information about its' state and problems
  * values - value of each parameter with its named-numbers or bits-activated value
* `pkt_types.json`, containing information about counts of each packet types in the file and their IDs and problems
* `summary.json`, containing information about counts of each parameter being OK, Warning or Error

## Usage
Clone the root directory of the repository. Check if all required software in __Requirements__ is installed. The packages with parentheses behind them are not required for the basic CLI functionality, but the features specified in parentheses will NOT work.

### CLI
The project is structured as a Python package, so you need to start by building the package and installing it.

To be able to do that, navigate to the directory, in which you cloned the project.
```
cd path/to/your/project_directory
```

Now you should be able to build the source distribution (note, python libraries `build` and `wheel` must be installed):
```
python setup.py sdist bdist_wheel
```

Lastly, install the package you just built by executing:
```
pip install .
```


__Usage:__

1. To start a new session of the script, create a class object of `Instance`:
   ```
   karloss = Karloss.Instance(config_location='PATH\\TO\\CONFIG.JSON')
   ```
   In the root project directory, an `example_config.json` is provided, which uses ASN.1 definitions from the `example_data/` directory.

2. To import a pcap file, call method `import_file()` of the object:
   ```
   karloss.import_file(input_file='PATH\\TO\\PCAP\\FILE')
   ```
   In the `example_data/` directory, a few data capture files are provided for testing.

4. Call the `analyse()` method to launch the analysis:
   ```
   karloss.analyse()
   ```

5. To output the results of a successful analysis, call the `output_results()` method:
   ```
   karloss.output_results(output_location='PATH\\TO\\OUTPUT\\DIRECTORY')
   ```

6. To plot a map using `folium`, call the `plot_map()` method:
   ```
   karloss.plot_map(packet_types=['LIST', 'OF', 'CONFIGURED', 'MESSAGES'], output_location='PATH\\TO\\OUTPUT\\DIRECTORY', group_markers=True)
   ```
   __Note:__ 
   * For each packet type specified under the `packet_types` parameter, there must be an entry in the config `mapData` section, otherwise the method will throw an exception. This config contains paths of the parameters needed for plotting the data points into the map. 
   * The `group_markers` parameter determines whether the datapoints will be grouped under Folium's `MarkerCluster`. This significantly improves browseability of the map, as the CPU does not have to generate thousands of datapoints in far zoom, though is worse for visual data representation.

The core script enables logging each session into the `log` directory in the script root. Cache is also implemented, meaning that for repeated analysis of the same file, packets are imported from cache. If the analysis were to be interrupted, the script should pick up where it left off after launching the analysis again for the same file.

### GUI
The usage of the GUI is fairly straightforward, although some features are not implemented. You should be able to just launch the `launch_gui.py` file in the root of project using console:
```
python launch_gui.py
```

In the first window, you will be prompted to select the `config.json` file and the pcap file. After clicking `Accept Config`, a window with a text box will pop up. In this textbox, all of the output of CLI is provided. 

Click the `Analyse` button to start analysis.

After analysis completion, you can either click the `Export Results` button and select the output directory. Or you can `Plot Map`, which will prompt you which messages configured you can plot and whether you want to group markers or not, and to select the output file.
