# IoX Logger Configuration

## Required Permission

IoX Logger requires direct access to IoX in order to discover nodes and read their values.

On this Configuration page, enable:

**Allow Unrestricted ISY Access by Node Server**

This permission is required. Without it, IoX Logger cannot retrieve the IoX node catalog or log node values.

After enabling the permission, restart IoX Logger if it is already running.

## Web Interface

Once IoX Logger is running, open the web interface at:

    http://<eisy-ip-address>:8765

Replace `<eisy-ip-address>` with the IP address of your eisy.

For example:

    http://192.168.1.100:8765

The web interface is intended for use on your local network and does not currently provide user authentication.

## Creating a Logger

From the web interface:

1. Select an IoX source.
2. Select a node.
3. Select the value/driver to log.
4. Choose either On Change or Fixed Interval logging.
5. Create the logger.

Historical data can then be graphed or downloaded as CSV.
