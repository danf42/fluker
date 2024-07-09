# fluker

Gather network switch information for connected port

## Desciprtion

Fluke was written to help collect network switch information.  It uses Scapy to send and receive LLDP packets and also send ICMP packets to check connectivity.  

The results are printed to the screen and written to a file.  The file is useful when multiple reports are being tested.  

## Prerequisites

[Npcap](https://npcap.com/) must be installed on Windows and [lippcap](https://www.tcpdump.org/) must be installed on Linux/Mac for `fluker` to identify and communicate with the network interfaces.  [Wireshark](https://www.wireshark.org/) contains the necessary drives for `fluker` to work properly.  If [Wireshark](https://www.wireshark.org/) is already installed on the machine, no futher action is required.  

## Usage

1. Install the required Python modules

    ```bash
    python -m pip install -r requirements.txt
    ```

2. Executing Script

    ```bash
    usage: fluker.py [-h] [--passive] [--pingtest] [--ips [IPS ...]] [--output OUTPUT]

    Gather network switch information for connected port

    options:
    -h, --help       show this help message and exit
    --passive        Passively collect LLDP Traffic. Don't send broadcast packet (default: False)
    --pingtest       Perform Ping Test. Use --ips for a list of IPs to ping (default: False)
    --ips [IPS ...]  List of IPs to ping(Format: 8.8.8.8 9.9.9.9) (default: ['8.8.8.8'])
    --output OUTPUT  CSV File to save results (default: fluker_output.csv)
    ```

    ```bash
    # Example
    python .\fluker.py --pingtest --ips 8.8.8.8 9.9.9.9
    ```

    ***Note, on Linux systems `sudo` is required to execute the script***

    When fluker is launched, it will get the default interface and a list of all active interfaces.  It will prompt the user to check if the default interface should be used to execute the tests.  If not, it will ask the user to choose from the list of active interfaces.  The user's selection will be written to `.fluker_iface` so that it can be used again.

