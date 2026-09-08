# IoX Logger

IoX Logger records values from IoX nodes and node servers and provides a local web interface for viewing, graphing, and downloading logged data.

## Web Interface

After the plugin starts, open:

http://<eisy-ip-address>:8765

Replace `<eisy-ip-address>` with the IP address of your eisy.

## Features

- Log native IoX nodes and node server values
- On-change logging
- Fixed-interval logging
- Enable or disable individual loggers
- Edit logging intervals
- Graph recorded values
- Download CSV data
- Automatic CSV file rotation and storage management

## Storage

Logger data is stored in the plugin's local `data` directory.

CSV files are automatically rotated and old files are removed as storage limits are reached.

## IoX Access

This plugin requires unrestricted IoX access in order to discover and read nodes and node server values.
