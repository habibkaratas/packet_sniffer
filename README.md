# Packet Sniffer

This is a packet capture tool based on PyQt5. This application can be used to listen to network traffic and analyze packets passing through a specific network interface.

## Features

- Listen to network traffic and packet analysis
- Supports TCP and UDP protocols
- Traffic filtering on specific ports

## Requirements

- Python 3.x
- PyQt5
- scapy
- win32com (for Windows compatibility)

## Installation

1. Download and install Python from [Python's official website](https://www.python.org/).
2. Install the required Python packages by running the following commands in your terminal/command prompt:

    ```
    pip install PyQt5
    pip install scapy
    ```

3. For Windows users, install the `win32com` package by running the following command in your terminal/command prompt:

    ```
    pip install pypiwin32
    ```

## Usage

1. Run the application by executing the `packet_sniffer.py` file in your terminal/command prompt.
2. Select the network interface you want to listen on and the protocol in the interface.
3. Specify the ports you want to monitor.
4. Click the "Start" button to begin listening.
5. Press the "Stop" button to stop listening.

## License

This project is licensed under the MIT License.
