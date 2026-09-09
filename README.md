# IoX Logger

IoX Logger is a PG3x plugin for Universal Devices IoX that records node and driver values for historical analysis.

## Features

- Discovers native IoX nodes and installed plugin nodes
- Logs selected node values
- On-change or fixed-interval logging
- Local web interface
- Graph historical data
- Download CSV data
- Enable, disable, edit, and delete individual loggers
- Automatic CSV rotation and storage management

## Installation

Install **IoX Logger** from the PG3x Plugin Store.

### Required IoX Permission

IoX Logger requires direct access to IoX in order to discover nodes and read their values.

After installation:

1. Open **IoX Logger** in PG3x.
2. Go to the **Configuration** page.
3. Enable **Allow Unrestricted ISY Access by Node Server**.
4. Restart IoX Logger if prompted or if the plugin was already running.

This permission is required. Without it, IoX Logger cannot retrieve the IoX node catalog or log node values.

## Web Interface

After IoX Logger is running, open:

    http://<eisy-ip-address>:8765

Replace `<eisy-ip-address>` with the IP address of your eisy.

For example:

    http://192.168.1.100:8765

The web interface is intended for use on your local network. It currently does not provide user authentication and should not be exposed directly to the Internet.

## Creating a Logger

From the web interface:

1. Select an IoX source.
2. Select a node.
3. Select the value/driver to log.
4. Choose the logging mode:
   - **On Change** records a new value when it changes.
   - **Fixed Interval** records the value at the selected interval.
5. Create the logger.

Once data has been collected, it can be viewed as a graph or downloaded as a CSV file.

## Data Storage

Logger configuration and historical data are stored locally on the eisy.

IoX Logger automatically manages its data files and storage usage.

## Requirements

- Universal Devices eisy running PG3x
- IoX
- Unrestricted IoX access permission enabled for the plugin
- TCP port **8765** available on the eisy

## License

MIT License
