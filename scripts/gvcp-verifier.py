#!/usr/bin/env python3
""" Returns with exitcode 1 if /....., otherwise 0 (success)
    Parses tcpdump output to verify GVCP traffic
"""
import traceback
import sys
import re
from datetime import datetime

verbose = 0


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def sprint(*args, **kwargs):
    print(*args, file=sys.stdout, flush=True, **kwargs)


def get_timestamp():
    current_time = datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return timestamp


def show_usage():
    eprint("Usage: tcpdump -i eth0 udp port 3956 -X -ttttt -v | " + sys.argv[0] + " [-vvvvv] [-h]")
    eprint("  note: normal output reports only 'unusually late' replies, all normal traffic is ignored.\n")


def remove_empty(list_of_strings):
    return list(filter(None, list_of_strings))


def split_comma(line):
    delimiters = r'[,\s\(\)]+'
    return re.split(delimiters, line)


def as_hex(values):
    result = "["
    for value in values:
        result += f"{value:02X} "
    return result.strip() + "]"


# takes a string line "0x0000:  4500 002c 1a57 4000 4011 68de a9fe 0ac8  E..,.W@.@.h....."
# and returns "4500 002c 1a57 4000 4011 68de a9fe 0ac8" as a list of values
def parse_hex_data(input_str):
    result = []
    parts = input_str.split(" ")
    if len(parts) < 9:
        return []

    for value in parts[1:10]:
        if value == "":
            continue

        result += [int(value[0:2], 16)]
        result += [int(value[2:4], 16)]
    return result


def get_uint16(data, offset, end):
    # sprint("get_uint16: {}\n", as_hex(data))
    ip_header = 14
    if end-offset != 1 or len(data) < (end-ip_header):
        eprint("get_uint16 error ", as_hex(data), offset, end)
        return 0

    offset -= ip_header
    return 256 * data[offset] + data[offset+1]


def get_uint32(data, offset, end):
    # sprint("get_uint32: {}\n", as_hex(data))
    ip_header = 14
    if end-offset != 3 or len(data) < (end-ip_header):
        eprint("get_uint32 error ", as_hex(data), offset, end)
        return 0

    offset -= ip_header
    return (0x1000000 * data[offset]) + (0x10000 * data[offset+1]) + (0x100 * data[offset+2]) + data[offset+3]


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

    def as_string(self):
        if self == Command.Discovery:
            return "DISCOVERY_CMD"
        if self == Command.DiscoveryAck:
            return " DISCOVERY_ACK"
        if self == Command.ReadReg:
            return " READREG_CMD"
        if self == Command.ReadRegAck:
            return " READREG_ACK"
        if self == Command.WriteReg:
            return "WRITEREG_CMD"
        if self == Command.WriteRegAck:
            return "WRITEREG_ACK"
        if self == Command.ReadMem:
            return "READMEM_CMD"
        if self == Command.ReadMemAck:
            return "READMEM_ACK"
        return f"[{self:04X}]"


def get_cmd_for_reply(reply):

    command = reply.command
    if command == Command.DiscoveryAck:
        return Command.Discovery
    if command == Command.ReadMemAck:
        return Command.ReadMem
    if command == Command.ReadRegAck:
        return Command.ReadReg
    if command == Command.WriteRegAck:
        return Command.WriteReg

    result = command-1
    eprint(f"unknown reply {hex(command)}, returning {hex(result)}")
    return result


class Packet():

    ControlChannelPrivilege = 0xA00
    Heartbeat = 0x938
    GevTimestampControlReset = 0x944
    BinningHorizontal = 0x30324
    BinningVertical = 0x30344
    AcquisitionStart = 0x40024
    AcquisitionStop = 0x40044
    TriggerSoftware = 0x40224

    def __init__(self, cmd=Command(0), request_id=0, address=0, timestamp=0):
        self.command = cmd
        self.request_id = request_id
        self.address = address
        self.timestamp = timestamp      # offset in microseconds
        self.value = 0
        self.ipaddress = ""  # packet was part of the conversation with the host at this address

    def is_heartbeat(self):
        return self.command == Command.WriteReg and self.address == Packet.Heartbeat

    def command_as_string(self):
        if self.is_heartbeat():
            return "Heartbeat"
        if self.command == Command.WriteReg and self.address == Packet.TriggerSoftware:
            return "TriggerSoftware"
        if self.command == Command.WriteReg and self.address == Packet.AcquisitionStart:
            return "AcquisitionStart"
        if self.command == Command.WriteReg and self.address == Packet.AcquisitionStop:
            return "AcquisitionStop"
        if self.command == Command.WriteReg and self.address == Packet.GevTimestampControlReset:
            return "GevTimestampControlReset"
        if self.command == Command.WriteReg and self.address == Packet.BinningHorizontal:
            return "BinningHorizontal"
        if self.command == Command.WriteReg and self.address == Packet.BinningVertical:
            return "BinningVertical"
        if self.command == Command.ReadReg and self.address == Packet.ControlChannelPrivilege:
            return "ReadCCP"
        return self.command.as_string()

    def explain(self):
        return f"Command({self.command:04X})"

    def details(self):
        if self.command == Command.ReadReg:
            return f"{self.address:08X} (req {self.request_id})"
        if self.command == Command.WriteReg:
            return f"{self.address:08X} = {self.value:08X} (req {self.request_id})"
        return ""

    def is_reply(self):
        return "ACK" in self.command.as_string()

    def is_command(self):
        return "CMD" in self.command.as_string()

    # am I a reply to 'packet', typically a stored packet is passed
    def is_ack_for(self, packet):
        command = get_cmd_for_reply(self)
        if packet.command == command and self.request_id == packet.request_id and self.ipaddress == packet.ipaddress:
            return True
        return False


def create_gvcp_packet(payload, timestamp_us, ipaddress):
    if len(payload) < 32:
        return Packet()

    cmd = get_uint16(payload, 44, 45)
    request_id = get_uint16(payload, 48, 49)

    packet = Packet(Command(cmd), request_id, 0, timestamp_us)
    packet.ipaddress = ipaddress

    if cmd == Command.ReadReg:
        packet.address = get_uint32(payload, 50, 53)

    if cmd == Command.WriteReg:
        packet.address = get_uint32(payload, 50, 53)
        packet.value = get_uint32(payload, 54, 57)
    return packet


def read_stdin():
    return sys.stdin.readline().strip()


def is_old(timestamp, now):
    return now - timestamp > 100000  # us, == 100ms


# we do not use datetime.strptime because this is not a 'wall clock' but a duration
# which means it can exceed 24 hours
def timestamp_to_microseconds(timestamp):
    hours, minutes, seconds_microseconds = timestamp.split(":")
    seconds, microseconds = seconds_microseconds.split(".")

    hours = int(hours)
    minutes = int(minutes)
    seconds = int(seconds)
    microseconds = int(microseconds)
    return (hours * 3600 + minutes * 60 + seconds) * 10**6 + microseconds


class Statistics:
    VerifiedCommands = 0
    LateCommands = 0
    TimeoutCommands = 0
    Addresses = set()


stats = Statistics()


def print_statistics():
    global stats
    eprint(f"{stats.VerifiedCommands} commands verified from {len(stats.Addresses)} sources.")
    eprint(f"Sources: {stats.Addresses}")

    eprint(f"{stats.LateCommands} commands late. (> {GVCP_Parser.Late/1000}ms)")
    eprint(f"{stats.TimeoutCommands} commands timed out. (> {GVCP_Parser.Timeout/1000}ms)")


class GVCP_Parser:
    def __init__(self):
        self.registry = []

    Late = 4000  # 4ms
    Timeout = 100000  # 100ms

    last_statistic_print = 0
    new_statistics = False

    def check_reply(self, reply_packet):
        global stats
        new_registry = []
        for stored_packet in self.registry:
            age = reply_packet.timestamp - stored_packet.timestamp
            if reply_packet.is_ack_for(stored_packet):
                if age > GVCP_Parser.Late:
                    sprint(f"{get_timestamp()} {reply_packet.ipaddress} cmd + reply = OK {stored_packet.command_as_string()} {stored_packet.details()} with request_id {reply_packet.request_id} after {age/1000}ms")
                    stats.LateCommands = stats.LateCommands + 1
                else:
                    stats.VerifiedCommands = stats.VerifiedCommands + 1
                # normal "ok" path, do not re-add this packet, because it was replied to.
                continue

            if age > GVCP_Parser.Timeout:
                sprint(f"{get_timestamp()} {stored_packet.ipaddress} Timeout for {stored_packet.command_as_string()} {stored_packet.details()} with request_id {stored_packet.request_id} after {age / 1000}ms")
                stats.TimeoutCommands = stats.TimeoutCommands + 1

            else:
                # not the command we're looking for, put it back
                new_registry += [stored_packet]
        self.registry = new_registry
        # sprint("len:", len(self.registry))

    def check_command(self, packet):
        for stored_packet in self.registry:
            age = packet.timestamp - stored_packet.timestamp
            if age > GVCP_Parser.Late:
                msg = f"{get_timestamp()} {stored_packet.ipaddress} command {stored_packet.command_as_string()} {stored_packet.details()}"
                sprint(f"{msg} [when req {packet.request_id} arrived] still waiting after {age/1000}ms")

    def register_command(self, packet):
        self.check_command(packet)
        self.registry += [packet]

    def administer(self, packet):
        if packet.is_heartbeat():
            return
        if packet.is_reply():
            self.check_reply(packet)
            return

        if packet.is_command():
            self.register_command(packet)
            return

        eprint(f"{get_timestamp()} unknown packet: {packet.explain()}")
        return

    def get_address(self, source_destination):
        ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.3956'
        ip_addresses = re.findall(ip_pattern, source_destination)
        if len(ip_addresses) != 1:
            return "<no gvcp address>"

        result = ip_addresses[0]
        stats.Addresses.add(result)
        return result

    def verbose_output(self, values, packet):
        if packet.is_heartbeat() and not verbose > 3:
            return

        if packet.command != Command.WriteReg and not verbose > 2:
            return

        length = len(values) + 14  # add 14 to get the length as shown in wireshark (with includes the ip-header)

        if verbose > 0:
            extra = f"{packet.command_as_string()} "
            if verbose > 1:
                extra = f"{packet.command_as_string()[:12]} {as_hex(values)} LEN {length} "
            sprint(f"{packet.timestamp}: {packet.ipaddress:15} {extra}{packet.details()}")

    def parse(self, udp_header, source_destination, data_lines):
        udp = remove_empty(split_comma(udp_header))
        timestamp = timestamp_to_microseconds(udp[0])

        ipaddress = self.get_address(source_destination)[:-5]

        values = []
        for line in data_lines:
            values += parse_hex_data(line)

        packet = create_gvcp_packet(values, timestamp, ipaddress)
        self.administer(packet)
        self.verbose_output(values, packet)

    def process(self):
        udp_header = ""
        data = []

        running = True
        while (running):
            line = read_stdin()
            if ", proto UDP" in line:   # sync'd on first line
                udp_header = line
                source_destination = read_stdin()
                data = [read_stdin()]
                data += [read_stdin()]
                data += [read_stdin()]
                self.parse(udp_header, source_destination, data)
        return 0


def main():
    global verbose
    if "-v" in sys.argv:
        verbose = 1
    if "-vv" in sys.argv:
        verbose = 2
    if "-vvv" in sys.argv:
        verbose = 3
    if "-vvvv" in sys.argv:
        verbose = 4
    if "-vvvvv" in sys.argv:
        verbose = 5
    if "-h" in sys.argv:
        show_usage()
        return 0

    parser = GVCP_Parser()
    return parser.process()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint("\ngige-monitor stopped.")
        print_statistics()
        sys.exit(2)
    except Exception:
        traceback.print_exc(file=sys.stderr)
    show_usage()
    sys.exit(999)
