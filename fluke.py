"""
Perform Network Switch Information Gathering and Check Connectivity
Fluke like script
"""
import argparse
import socket
from scapy.contrib.lldp import *
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import survey


# Useful Resources
# - https://scapy.readthedocs.io/en/latest/api/scapy.contrib.lldp.html

# Globals with static values
LLDP_BROADCAST_MAC = "01:80:c2:00:00:0e"
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

# Globals to modify
status_dict = {}

def str2bool(v):
    '''Process True/False input from user'''
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        return None


def parse_arguments():
    '''
    Parse command line arguments
    '''

    parser = argparse.ArgumentParser(description='Ethernet Port Integration Tool')
    parser.add_argument('--passive', action='store_true', help='Passively collect LLDP Traffic.  Don\'t send broadcast packet')
    parser.add_argument('--pingtest', action='store_true', help='Perform Ping Test.  Use --ips for a list of IPs to ping')
    parser.add_argument('--ips', help='List of IPs to ping(Format:  8.8.8.8 9.9.9.9)', nargs='*', default=['8.8.8.8'])
    cargs = parser.parse_args()

    return cargs


def is_valid_ip(ip_addr:str) -> bool:
    '''Return if the IP address is valid'''
    try:
        socket.inet_aton(ip_addr)
        return True
    except:
        return False


def get_valid_ips(ip_list:list) -> list:
    '''Return a list of valid IP addresses'''

    valid_ips = []
    for ip in ip_list:
        if is_valid_ip(ip):
            valid_ips.append(ip)

    return valid_ips


def lldp_packet_handler(pkt):
    '''Handle LLDP Responses'''

    global status_dict

    if pkt.haslayer(LLDPDU):

        if pkt.haslayer(LLDPDUChassisID):
            chassis_id=pkt[LLDPDUChassisID].id
            status_dict['chassis_id'] = chassis_id

        if pkt.haslayer(LLDPDUPortID):
            port_id=pkt[LLDPDUPortID].id
            status_dict['port_id'] = port_id

        if pkt.haslayer(LLDPDUSystemName):
            system_name=(pkt[LLDPDUSystemName].system_name).decode('utf-8')
            status_dict['system_name'] = system_name

        if pkt.haslayer(LLDPDUPortDescription):
            port_description=(pkt[LLDPDUPortDescription].description).decode('utf-8')
            status_dict['port_description'] = port_description

        if pkt.haslayer(LLDPDUSystemDescription):
            system_description=(pkt[LLDPDUSystemDescription].description).decode('utf-8')
            status_dict['system_description'] = system_description

        # Array index for LLDPDUGenericOrganisationSpecific layers
        i = 0

        # Loop through the layers looking for LLDPDUGenericOrganisationSpecific layers
        for layer in pkt.payload.layers():

            if layer == LLDPDUGenericOrganisationSpecific:

                # This is the org code for VLAN Information
                if 32962 == pkt[LLDPDUGenericOrganisationSpecific][i].org_code:

                    # Network byte order is big-endian
                    vlanid = int.from_bytes(pkt[LLDPDUGenericOrganisationSpecific][i].data, byteorder='big')
                    status_dict['vlanid'] = vlanid

                i = i + 1


def switch_discovery(passive_only:bool, iface:dict):
    '''Collect LLDP Informatioin from Switch'''

    # Get information from the interface dict
    mac = iface['iface_mac']
    ip  = iface['iface_ip']
    name = iface['iface_name']
    idx = iface['iface_index']

    # Build the LLDP Packet
    eth = Ether(dst=LLDP_BROADCAST_MAC, type=0x88cc)
    chassis_id =    LLDPDUChassisID(subtype=int("0x04",16), id=mac)
    port_id =       LLDPDUPortID(subtype=int("0x03", 16), id=mac)
    ttl =           LLDPDUTimeToLive(ttl=4)
    system_name =   LLDPDUSystemName(system_name=b'LinkIQ')
    system_cap =    LLDPDUSystemCapabilities(
                        router_available=1,
                        mac_bridge_available=1,
                        wlan_access_point_available=1,
                        station_only_available=1,
                        station_only_enabled=1)
    port_desc =     LLDPDUPortDescription(description=name)
    mgmt_addr =     LLDPDUManagementAddress(
                        management_address_subtype=int("0x01", 16),
                        management_address=socket.inet_aton(ip),
                        interface_numbering_subtype=2,
                        interface_number=idx)
    end_llpdu =     LLDPDUEndOfLLDPDU()

    # Build the Layer 2 Frame
    frame = eth / chassis_id / port_id / ttl / system_name / system_cap / port_desc / mgmt_addr / end_llpdu

    # Send the frame for active testing
    if not passive_only:
        sendp(frame, iface=name)

    # Sniff for LLDP packets on the interface
    sniff(iface=name, prn=lldp_packet_handler, filter=f"ether dst {LLDP_BROADCAST_MAC}", count=1)


def ping(ipaddr:str, interface:str) -> None:
    '''Perform ping test against ip address'''

    global status_dict

    pkt = IP(dst=f"{ipaddr}")/ICMP(id=1)
    resp = sr1(pkt, timeout=1, iface=interface, verbose=False)

    if resp:
        status_dict[f'ping_{ipaddr}'] = (True, resp.src)

    else:
        status_dict[f'ping_{ipaddr}'] = (False, None)


def get_default_network_iface() -> tuple:
    '''Return the Default Network Interface's IP and MAC Address'''

    ipaddr = get_if_addr(conf.iface)
    macaddr = get_if_hwaddr(conf.iface)

    return (ipaddr, macaddr)


def get_network_ifaces() -> dict:
    '''Return a Dictionary of Interfaces with assigned IP Addresses'''

    iface_dict = {}

    ifacelist = get_working_ifaces()

    for interface in ifacelist:

        if interface.ip:
            iface_dict[interface.ip] = {
                'iface_name':interface.name,
                'iface_desc':interface.description,
                'iface_ip':interface.ip,
                'iface_mac':interface.mac,
                'iface_index':interface.index
            }

    return iface_dict


def get_usable_interface() -> dict:
    '''Prompt the user to select Interface to use for testing'''

    # Get all the valid interfaces
    iface_dict = get_network_ifaces()

    # Get the Default IP and Mac
    ipaddr, macaddr = get_default_network_iface()

    # Get the Default interface name
    ifacename = iface_dict[ipaddr]['iface_name']

    question = f"Is this the interface to use for the test: {ifacename}, {ipaddr}, {macaddr} "
    ans = survey.routines.inquire(question, default=True)

    if not ans:
        choice_list = []
        for _, value in iface_dict.items():
            choice_list.append(f"{value['iface_name']}, {value['iface_ip']}, {value['iface_mac']}")

        index = int(survey.routines.select('Select Interface to use: ', options = choice_list))

        selected = choice_list[index]
        ipaddr = selected.split(",")[1].strip()

    return iface_dict[ipaddr]


def pretty_print_status(status:dict) -> None:
    '''Pretty Print the Status the Screen'''

    chassis_id = status.get('chassis_id', 'UNK')
    port_id = status.get('port_id', 'UNK')
    system_name = status.get('system_name', 'UNK')
    port_description = status.get('port_description', 'UNK')
    system_description = status.get('system_description', 'UNK')
    vlanid = status.get('vlanid', 'UNK')

    print("\n**** Switch Information *****")
    print(f"Chassis ID: {chassis_id}")
    print(f"Port ID: {port_id}")
    print(f"System Name: {system_name}")
    print(f"Port Description: {port_description}")
    print(f"System Description: {system_description}")
    print(f"VLAN ID: {vlanid}")

    print("\n**** Port Connectivity *****")
    for key,value in status.items():
        if 'ping' in key:
            is_reachable, src_addr = value
            if is_reachable:
                print(f"Ping Successfull for {src_addr }")
            else:
                print(f"Ping NOT Successfull for {src_addr }")

def main(input_args):
    '''Main Program Function'''

    # Get the command line arguments
    do_passive = input_args.passive
    do_pingtest = input_args.pingtest
    ip_list = get_valid_ips(input_args.ips)

    # Get the interface to use for testing
    iface_dict = get_usable_interface()

    # Perform LLDP Discovery
    switch_discovery(do_passive, iface_dict)

    # Perform Ping Test based on user input
    if do_pingtest:

        iface_name = iface_dict['iface_name']

        for ip in ip_list:
            ping(ip, iface_name)

    # If we have status, print everything out
    if status_dict:
        pretty_print_status(status_dict)


if __name__ == '__main__':
    args = parse_arguments()
    main(args)
