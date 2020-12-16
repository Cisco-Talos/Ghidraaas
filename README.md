# Ghidraaas - Ghidra as a Service

Ghidraaas is a simple web server that exposes Ghidra analysis through REST APIs. The project includes three Ghidra plugins to analyze a sample, get the list of functions and to decompile a function.

Ghidraaas is also the backend of [GhIDA](https://github.com/Cisco-Talos/GhIDA), the IDA plugin that integrates the Ghidra decompiler in IDA Pro.


## How does it work?

Ghidraaas uses Ghidra [Headless Analyzer](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html) to analyze the submitted sample. Then, the Ghidra project (the `*.gpr` file and the `*.rep` folder) is kept on the server until the `analysis_terminated` API is called. Three Ghidra [Python plugins](ghidra_plugins) are called by the Headless Analyzer on the sample's project to extract the list of functions and to decompile the requested function.


## Features

Ghidraaas implements generic APIs to analyze a sample, get the list of functions and the decompiled code of a function, but it also includes some specific APIs to interact with the GhIDA plugin.

Ghidraaas generic APIs:

* `api/analyze_sample/` Submit a sample for the analysis 

* `api/get_functions_list/<sha256>` Request the list of functions 

* `api/get_functions_list_detailed/<sha256>` Request the list of functions with additional details

* `api/get_decompiled_function/<sha256>/<offset>` Request to decompile a function

* `api/analysis_terminated/<sha256>` Remove the `*.gpr` file and `*.rep` project folder related to the sample.

GhIDA specific APIs:

* `api/ida_plugin_checkin/` Sample check-in

* `api/ida_plugin_get_decompiled_function/` Decompile function

* `api/ida_plugin_checkout/` Sample check-out.


An example on how to use the APIs can be found in [test.py](tests/test.py).

## Installation

### Lazy installation with Docker

[docker_config.json](config/docker_config.json) contains the configuration file of Ghidraaas (no changes are needed).

* Build *ghidraaas*
```
docker build -t ghidraaas .
```

* Run *ghidraaas* docker
```
docker run -p 8080:8080 -t ghidraaas
```

* Test the APIs
```
cd tests
python3 test.py
```

### Manual installation (no docker)
* Create a Python3 virtual env
```
python3 -m virtualenv env
source env/bin/activate
```

* Install the required packages
```
pip install -r requirements.txt
```

* Download and unzip the latest Ghidra release
```
wget -O ghidra.zip https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip
unzip ghidra.zip
rm ghidra.zip
```

* Set the `ghidra_9.1.2_PUBLIC` folder path in `GHIDRA_PATH` of [config.json](config/config.json)

* Launch the server
```
gunicorn -w 2 -t 300 -b 0.0.0.0:8080 flask_api:app
```

* Test the APIs. Open another terminal and type:
```
cd tests
python3 test.py
```

## Bugs and suggestion

If you discover a bug, or you have any improvements or suggestions, please open an [issue](https://github.com/Cisco-Talos/Ghidraaas/issues/new).

Be sure to include as many details as possible in order to reproduce the bug.


## License

Ghidraaas is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)

The original `Dockerfile` and `launch.sh.patch` are from [bskaggs/ghidra-docker](https://github.com/bskaggs/ghidra-docker).
