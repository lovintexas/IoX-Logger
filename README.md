# IoX Logger

**Version 1.1.4**

IoX Logger is a plugin for Universal Devices IoX that records node values and program executions for historical analysis.

## Documentation

Full documentation and setup guide:

https://lovintexas.github.io/IoX-Logger/

## Features

### Node Logging
- Discover native IoX nodes and installed plugin nodes
- Record selected node and driver values
- On-change or fixed-interval logging
- Graph historical data
- Download CSV data
- Enable, disable, edit, and delete individual loggers
- Automatic CSV rotation and storage management

### Program Execution Logging
- Monitor IoX program THEN and ELSE executions
- Enable or disable program logging
- Store execution history in SQLite
- Configure automatic history retention (7–365 days)
- Search and sort execution history in the web interface
- Download program execution history as CSV
- Monitor all discovered IoX programs without modifying them

### Web Interface
- HTTPS on port 8765 with automatic HTTP-to-HTTPS redirection
- Administrator password protection
- First-time password setup
- Session-based login and logout
- Password change and recovery
- Searchable program execution history

## Installation

Install **IoX Logger** from the Universal Devices Plugin Store.

### Required IoX Permission

IoX Logger requires direct access to IoX to discover nodes and read their values.

After installation:

1. Open **IoX Logger** in PG3x.
2. Go to **Configuration**.
3. Enable **Allow Unrestricted ISY Access by Node Server**.
4. Restart the plugin if necessary.

## Web Interface

Open:

    https://<eisy-ip-address>:8765

For example:

    https://192.168.1.100:8765

The HTTPS certificate is locally generated and self-signed. Your browser may display a certificate warning.

On first use, create an administrator password. Subsequent visits require login.

Keep the web interface restricted to your trusted local network.

## Creating a Node Logger

1. Select an IoX source.
2. Select a node.
3. Select the value or driver.
4. Choose On Change or Fixed Interval logging.
5. Create the logger.

Historical values can be graphed or downloaded as CSV files.

## Program Logger

Program Logger monitors executions of IoX programs using the native IoX event stream.

### Credentials

Enter your **local IoX administrator credentials** in the Program Monitor section.

**Not Portal Credentials.**

These credentials are separate from the IoX Logger web interface password.

### Configuration

- Enable or disable program logging.
- Select the retention period.
- Search and sort execution history.
- Download execution history as CSV.

Program history is stored locally in SQLite.

## Data Storage

Node logging uses automatically rotated CSV files.

Program execution history is stored in a separate SQLite database with configurable retention.

Configuration, credentials, and historical data are stored locally on the eisy.

## Requirements

- Universal Devices eisy running a compatible plugin environment
- IoX
- Unrestricted IoX access permission
- TCP port 8765 available
- Local IoX credentials for program monitoring

## License

MIT License
