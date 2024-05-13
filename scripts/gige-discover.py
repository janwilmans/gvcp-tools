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
import struct
import time

verbose = 0
gvcp_port = 3956
camera_count = 0


def as_hex(values):
    result = "["
    for value in values:
        result += f"{value:02X} "
    return result.strip() + "]"


def is_discover_ask(data):
    return len(data) >= 4 and data[0:4] == b'\x00\x00\x00\x03'


def get_uint16(data, offset, end):
    header = 44
    if end - offset != 1 or len(data) < (end - header):
        print("get_uint16 error ", as_hex(data), offset - header, end - header)
        return 0

    offset -= header
    return 256 * data[offset] + data[offset + 1]


def get_two_uint16(data, offset, end):
    header = 44
    if end - offset != 3 or len(data) < (end - header):
        print("get_two_uint16 error ", as_hex(data), offset, end)
        return 0

    offset -= header
    return (0x100 * data[offset]) + data[offset + 1], (0x100 * data[offset + 2]) + data[offset + 3]


def get_uint32(data, offset, end):
    header = 44
    if end - offset != 3 or len(data) < (end - header):
        print("get_uint32 error ", as_hex(data), offset, end)
        return 0

    offset -= header
    return (0x1000000 * data[offset]) + (0x10000 * data[offset + 1]) + (0x100 * data[offset + 2]) + data[offset + 3]


def get_hex_bytes(data, offset, end):
    header = 44
    if len(data) < (end - header):
        print("get_hex_bytes error ", as_hex(data), offset, end)
        return []

    offset -= header

    hex_data = data.hex()
    result = []
    for i in range(0, 6):
        index = (offset * 2) + (i * 2)
        result += [hex_data[index:index + 2]]
    return result


def get_decimal_bytes(data, offset, end):
    header = 44
    if len(data) < (end - header):
        print("get_decimal_bytes error ", as_hex(data), offset, end)
        return []

    offset -= header

    result = []
    for index in range(offset, offset + 4):
        result += [str(data[index])]
    return result


def get_string(data, offset, end):
    header = 44
    if len(data) < (end - header):
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


class Command(int):
    Unreadable = 0
    Discovery = 0x2
    DiscoveryAck = 0x3
    ReadReg = 0x80
    ReadRegAck = 0x81
    WriteReg = 0x82
    WriteRegAck = 0x83
    ReadMem = 0x84
    ReadMemAck = 0x85


class Device:
    def __init__(self, response):
        self.response = response

    def address(self):
        return self.response.current_ip

    def evaluate_status(self, status):
        GEV_STATUS_ACCESS_DENIED = 0x8006
        if status == 0:
            return
        if (status == GEV_STATUS_ACCESS_DENIED):
            print(f"  access denied! ({status:X})")
        else:
            print(f"  status: {status:X}")

    def readreg_cmd(self, memory_address):
        readreg_message = b'\x42\x01\x00\x80\x00\x04\x00\x4a'  # x04 - length, x00 x4a - req. id
        readreg_message += struct.pack('>I', memory_address)
        data = send_gvcp(self.address(), readreg_message)
        status = get_uint16(data, 44, 45)
        command = get_uint16(data, 46, 47)
        # length = get_uint16(data, 48, 49)
        # payload_id = get_uint16(data, 50, 51)
        if status == 0 and command == Command.ReadRegAck:
            return get_uint32(data, 52, 55)

        print("readreg_cmd received invalid response.", data.hex())
        return 0

    def writereg_cmd(self, memory_address, value):
        # print(f"writereg_cmd: {memory_address:X} = {value:X}")

        writereg_message = b'\x42\x01\x00\x82\x00\x08\x00\x4b'  # x08 - length, x00 x4b - req. id
        writereg_message += struct.pack('>I', memory_address)
        writereg_message += struct.pack('>I', value)
        data = send_gvcp(self.address(), writereg_message)
        status = get_uint16(data, 44, 45)
        command = get_uint16(data, 46, 47)
        if command != Command.WriteRegAck:
            print("writereg_cmd received invalid response.", data.hex())
        self.evaluate_status(status)
        return status

    def reset(self):
        print("ResetDevice:", self.address())
        address = 0xfffffff0
        value = self.readreg_cmd(address)
        self.writereg_cmd(address, value | 0x1)  # or just force value 0x80000001

    def summary(self):
        response = self.response
        return f"{response.current_ip:15} {response.netmask:15}: {response.vendor} {response.model} {response.device_version}, Serial: {response.serial_number}"


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


def print_all_details(device):
    print("Response from device:")
    response_members = vars(device.response)
    for key, value in response_members.items():
        print(f"  {key:32}: {value}")


def handle_incoming_udp(data, addr):
    global camera_count
    if verbose > 2:
        print(f"Received {addr}: {data.hex()}")
    # Check if the response is a DISCOVER_ACK
    if is_discover_ask(data):
        if verbose > 1:
            print(f"Received DISCOVER_ACK {addr}: {len(data)} {data.hex()}")
        device = Device(decode(data))
        camera_count = camera_count + 1
        if verbose == 0:
            print(device.summary())
        if verbose >= 1:
            print_all_details(device)


def send_gvcp(address, data):

    # print(f"send_gvcp: ", address, data.hex())
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set a timeout for receiving responses (in seconds)
    udp_socket.settimeout(5)

    response_data = []
    try:
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_socket.sendto(data, (address, gvcp_port))

        response_data, _ = udp_socket.recvfrom(1024)

    except socket.error as e:
        if str(e) != "timed out":
            print("The Error:", e)
    finally:
        udp_socket.close()

    return response_data


def send_broadcast(source_address):

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.bind((source_address, gvcp_port))

    # Define the GVCP discover message
    # x42\x01 means:
    # x42 == Discover message key
    # x19 == x01 (Acknowledge Required) + x10 (Allow Broadcast Acknowledge) + x08 (Unknown!)
    discover_broadcast_message = b'\x42\x19\x00\x02\x00\x00\xff\xff'
    broadcast_address = "255.255.255.255"
    udp_socket.sendto(discover_broadcast_message, (broadcast_address, gvcp_port))
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


def get_subnet_addresses():
    result = []
    for ip_address in get_ip_addresses():    # example: '172.16.2.1/24'
        result += [calculate_broadcast_address(ip_address)]
    return result   # example: '172.16.2.255'


def get_source_addresses():
    result = []
    for ip_address in get_ip_addresses():   # example: '172.16.2.1/24'
        result += [calculate_source_address(ip_address)]
    return result  # example: '172.16.2.1'


def gvcp_discover(source_addresses):
    global camera_count
    camera_count = 0

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.bind(("0.0.0.0", gvcp_port))

    for source_address in source_addresses:
        send_broadcast(source_address)

    udp_socket.settimeout(2)
    start_time = time.monotonic()
    try:
        # Listen for responses
        while ((time.monotonic() - start_time) < 2):
            data, addr = udp_socket.recvfrom(1024)
            handle_incoming_udp(data, addr)

    except socket.error as e:
        if str(e) != "timed out":
            print("The Error:", e)
    finally:
        udp_socket.close()
        print(f"Found {camera_count} cameras.")


def get_option_from_command_line(option):
    if option in sys.argv:
        index = sys.argv.index(option)
        if len(sys.argv) > index + 1:
            return sys.argv[index + 1]
    return None


def main():
    global verbose
    if "-v" in sys.argv:
        verbose = 1
    if "-vv" in sys.argv:
        verbose = 2
    if "-vvv" in sys.argv:
        verbose = 3
    if "-h" in sys.argv:
        show_usage()
        return 0

    return gvcp_discover(get_source_addresses())


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
