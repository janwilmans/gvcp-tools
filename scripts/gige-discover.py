#!/usr/bin/env python3
""" Returns with exitcode 1 if /....., otherwise 0 (success)
    discover GigE Vision devices and report information from them
    part of: https://github.com/janwilmans/gvcp-tools
"""

import socket
import sys
import traceback
import subprocess
import re
import ipaddress
import threading

verbose = 0
gvcp_port = 3956


def as_hex(values):
    result = "["
    for value in values:
        result += f"{value:02X} "
    return result.strip() + "]"


def is_discover_ask(data):
    return len(data) >= 4 and data[0:4] == b'\x00\x00\x00\x03'


def get_uint16(data, offset, end):
    header = 44
    if end-offset != 1 or len(data) < (end-header):
        print("get_uint16 error ", as_hex(data), offset, end)
        return 0

    offset -= header
    return 256 * data[offset] + data[offset+1]


def get_two_uint16(data, offset, end):
    header = 44
    if end-offset != 3 or len(data) < (end-header):
        print("get_two_uint16 error ", as_hex(data), offset, end)
        return 0

    offset -= header
    return (0x100 * data[offset]) + data[offset+1], (0x100 * data[offset+2]) + data[offset+3]


def get_uint32(data, offset, end):
    header = 44
    if end-offset != 3 or len(data) < (end-header):
        print("get_uint32 error ", as_hex(data), offset, end)
        return 0

    offset -= header
    return (0x1000000 * data[offset]) + (0x10000 * data[offset+1]) + (0x100 * data[offset+2]) + data[offset+3]


def get_hex_bytes(data, offset, end):
    header = 44
    if len(data) < (end-header):
        print("get_hex_bytes error ", as_hex(data), offset, end)
        return []

    offset -= header

    hex_data = data.hex()
    result = []
    for i in range(0, 6):
        index = (offset*2) + (i*2)
        result += [hex_data[index:index+2]]
    return result


def get_decimal_bytes(data, offset, end):
    header = 44
    if len(data) < (end-header):
        print("get_decimal_bytes error ", as_hex(data), offset, end)
        return []

    offset -= header

    result = []
    for index in range(offset, offset+4):
        result += [str(data[index])]
    return result


def get_string(data, offset, end):
    header = 44
    if len(data) < (end-header):
        print("get_bytes error ", as_hex(data), offset, end)
        return []

    offset -= header
    end -= header

    result = ""
    for index in range(offset, end):
        value = data[index]
        if value == 0:
            break
        result += chr(data[index])
    return result


class Response:
    status = 0
    status = 0
    command = 0
    length = 0
    payload_id = 0
    spec_version = ""
    device_mode = ""
    mac_address = ""
    supported_ip_configurations = ""
    current_ip_configuration = ""
    current_ip = ""
    netmask = ""
    gateway = ""
    vendor = ""
    model = ""
    device_version = ""
    manufacturer_info = ""
    serial_number = ""
    user_defined_name = ""


def decode(data):
    result = Response()
    result.status = get_uint16(data, 44, 45)
    result.command = get_uint16(data, 46, 47)
    result.length = get_uint16(data, 48, 49)
    result.payload_id = get_uint16(data, 50, 51)
    major, minor = get_two_uint16(data, 52, 55)
    result.spec_version = f"{major}.{minor}"
    result.device_mode = f"{get_uint32(data, 56, 59):X}"
    result.mac_address = ":".join(get_hex_bytes(data, 62, 67))
    result.supported_ip_configurations = f"{get_uint32(data, 68, 71):X}"
    result.current_ip_configuration = f"{get_uint32(data, 72, 75):X}"
    result.current_ip = ".".join(get_decimal_bytes(data, 88, 91))
    result.netmask = ".".join(get_decimal_bytes(data, 104, 107))
    result.gateway = ".".join(get_decimal_bytes(data, 120, 123))
    result.vendor = get_string(data, 124, 155)
    result.model = get_string(data, 156, 187)
    result.device_version = get_string(data, 188, 219)
    result.manufacturer_info = get_string(data, 220, 267)
    result.serial_number = get_string(data, 268, 283)
    result.user_defined_name = get_string(data, 284, 299)
    return result


def print_summary(response):
    print(f"{response.current_ip:15} {response.netmask:15}: {response.vendor} {response.model} {response.device_version}, Serial: {response.serial_number}")


def print_all_details(response):
    print("Response from device:")
    response_members = vars(response)
    for key, value in response_members.items():
        print(f"  {key:32}: {value}")


def discover_multicast(multicast_address):

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Define the GVCP discover message
    discover_message = b'\x42\x01\x00\x02\x00\x00\xff\xff'

    # Set a timeout for receiving responses (in seconds)
    udp_socket.settimeout(5)

    try:
        print(f"GVCP GigE Vision multicast discover command to {multicast_address}")
        # Send the GVCP discover message
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.sendto(discover_message, (multicast_address, gvcp_port))

        # Listen for responses
        while True:
            data, addr = udp_socket.recvfrom(1024)  # Buffer size is 1024 bytes
            if verbose > 2:
                print(f"Received {addr}: {data.hex()}")
            # Check if the response is a DISCOVER_ACK
            if is_discover_ask(data):
                if verbose > 1:
                    print(f"Received DISCOVER_ACK {addr}: {len(data)} {data.hex()}")
                response = decode(data)
                if verbose == 0:
                    print_summary(response)
                if verbose >= 1:
                    print_all_details(response)

    except socket.error as e:
        if str(e) != "timed out":
            print("The Error:", e)
    finally:
        udp_socket.close()


def discover_broadcast(source_address):

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((source_address, gvcp_port))

    discover_broadcast_message = b'\x42\x19\x00\x02\x00\x00\xff\xff'
    broadcast_address = "255.255.255.255"

    # Set a timeout for receiving responses (in seconds)
    udp_socket.settimeout(5)

    try:
        print(f"GVCP GigE Vision broadcast discover command from {source_address} to {broadcast_address}")
        # Send the GVCP discover message
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.sendto(discover_broadcast_message, (broadcast_address, gvcp_port))

        # Listen for responses
        while True:
            data, addr = udp_socket.recvfrom(1024)  # Buffer size is 1024 bytes
            if verbose > 2:
                print(f"Received {addr}: {data.hex()}")
            # Check if the response is a DISCOVER_ACK
            if is_discover_ask(data):
                if verbose > 1:
                    print(f"Received DISCOVER_ACK {addr}: {len(data)} {data.hex()}")
                response = decode(data)
                if verbose == 0:
                    print_summary(response)
                if verbose >= 1:
                    print_all_details(response)

    except socket.error as e:
        if str(e) != "timed out":
            print("The Error:", e)
    finally:
        udp_socket.close()


def calculate_broadcast_address(ip_with_subnet):
    network = ipaddress.IPv4Network(ip_with_subnet, strict=False)
    return str(network.broadcast_address)


def calculate_source_address(ip_with_subnet):
    (address, _) = ip_with_subnet.split("/")
    return address


def get_ip_addresses():
    # Run the 'ip a' command and capture its output
    result = subprocess.run(['ip', 'a'], capture_output=True, text=True)
    output = result.stdout

    # Regular expression pattern to match broadcast addresses
    pattern = r'inet (\d+\.\d+\.\d+\.\d+/\d+)'

    ip_addresses = []
    for match in re.finditer(pattern, output):
        ip_addresses += list(match.groups(1))

    return ip_addresses


def get_multicast_addresses():
    result = []
    for ip_address in get_ip_addresses():    # example: '172.16.2.1/24'
        result += [calculate_broadcast_address(ip_address)]
    return result   # example: '172.16.2.255'


def get_source_addresses():
    result = []
    for ip_address in get_ip_addresses():   # example: '172.16.2.1/24'
        result += [calculate_source_address(ip_address)]
    return result  # example: '172.16.2.1'


def gvcp_broadcast(source_addresses):

    threads = []
    for source_address in source_addresses:
        thread = threading.Thread(target=discover_broadcast, args=(source_address,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def gvcp_discover(multicast_addresses):

    threads = []
    for multicast_address in multicast_addresses:
        thread = threading.Thread(target=discover_multicast, args=(multicast_address,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def get_option_from_command_line(option):
    if option in sys.argv:
        index = sys.argv.index(option)
        if len(sys.argv) > index + 1:
            return sys.argv[index + 1]
    return None


def main():
    global verbose
    broadcast = False
    if "-b" in sys.argv:
        broadcast = True
    if "-v" in sys.argv:
        verbose = 1
    if "-vv" in sys.argv:
        verbose = 2
    if "-vvv" in sys.argv:
        verbose = 3
    if "-h" in sys.argv:
        show_usage()
        return 0

    # source_address = get_option_from_command_line("-S")
    # broadcast_address = get_option_from_command_line("-B")

    if broadcast:
        return gvcp_broadcast(get_source_addresses())
    else:
        return gvcp_discover(get_multicast_addresses())


def show_usage():
    print("usage: gige-discover")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ngige-discover stopped.", file=sys.stderr)
        sys.exit(2)
    except Exception:
        traceback.print_exc(file=sys.stderr)
    show_usage()
    sys.exit(999)
