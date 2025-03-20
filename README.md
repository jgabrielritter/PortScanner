# Network Port Scanner

A web-based network port scanning tool built with Python and Flask that allows you to scan a target IP address or hostname for open ports.

## Features

- **Web Interface**: User-friendly web interface for easy port scanning
- **Flexible Scanning**: Scan common ports, custom port ranges, or all ports
- **Multithreaded**: Fast scanning using concurrent threads
- **Service Detection**: Identifies services running on open ports
- **Customizable Settings**: Adjust timeout and thread count for scanning

## Requirements

- Python 3.6+
- Flask

## Installation

1. Clone this repository or download the source code
2. Install the required dependencies:

```bash
pip install flask
```

## Usage

### Starting the Web Server

Run the following command in your terminal:

```bash
python port_scanner_backend.py
```

Then open your web browser and navigate to: `http://127.0.0.1:5000`

### Using the Web Interface

1. Enter a target IP address or hostname in the "Target" field
2. Select a port scanning option:
   - **Common Ports**: Scans a predefined list of frequently used ports
   - **Custom Port Range**: Define a specific range of ports to scan
   - **All Ports**: Scans all 65,535 ports (warning: this can take a long time)
3. Adjust the timeout and thread count as needed
4. Click "Start Scan" to begin scanning

### Command Line Usage

The tool also includes a command-line version:

```bash
python port_scanner.py <target> [start_port] [end_port]
```

Examples:
```bash
# Scan common ports
python port_scanner.py example.com

# Scan a range of ports
python port_scanner.py 192.168.1.1 1 1000
```

## How It Works

The port scanner works by attempting to establish TCP connections to ports on the target host:

1. The web interface collects user inputs for the target and scan parameters
2. The backend initiates multiple threads to scan ports concurrently
3. For each port, a socket connection is attempted:
   - If the connection succeeds, the port is marked as open
   - If the connection fails, the port is closed
4. The service name is determined for open ports where possible
5. Results are presented in a formatted table in the web interface

## Security and Legal Considerations

**Important**: Only scan hosts you have permission to scan. Unauthorized port scanning may be illegal in some jurisdictions and could violate terms of service of your internet provider.

## Technical Details

- **Frontend**: HTML, CSS, and JavaScript
- **Backend**: Python and Flask
- **Networking**: Uses Python's socket library for TCP connections
- **Concurrency**: Implements multithreading for parallel port scanning
- **API**: RESTful API endpoint for scan requests

## Limitations

- Only performs TCP connection scanning (SYN scanning is not implemented)
- Does not perform version detection beyond basic service identification
- Web interface runs on a development server (not recommended for production)

## License

This project is free to use for educational and ethical purposes.

## Author

J. Gabriel Ritter

## Acknowledgments

This tool was created for educational purposes to understand network scanning techniques and web application development.
