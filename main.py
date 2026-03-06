import sys
import socket
import struct

# only args are filename and hostname
if len(sys.argv) != 2:
    print("Too few or too many arguments, example: python3")
    sys.exit()

hostname = sys.argv[1]
print(f"Hostname: {hostname}")

# create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# google dns server
dns_server = ("8.8.8.8", 53)
print("DNS server:", dns_server)


# build dns header
transaction_id = 67
flags = 0x0100
question_count = 1
answer_count = 0
authority_count = 0
additional_count = 0

header = struct.pack(
    "!HHHHHH",
    transaction_id,
    flags,
    question_count,
    answer_count,
    authority_count,
    additional_count,
)

# encode hostname
encoded_hostname = b""
for part in hostname.split("."):
    encoded_hostname += bytes([len(part)])
    encoded_hostname += part.encode()

encoded_hostname += b"\x00"

# question section
record_type = 1  # A record
record_class = 1  # internet

question = encoded_hostname + struct.pack("!HH", record_type, record_class)

# send query and get response
dns_query = header + question
sock.sendto(dns_query, dns_server)
response, _ = sock.recvfrom(512)

# read response header
(
    response_id,
    flags,
    question_count,
    answer_count,
    authority_count,
    additional_count,
) = struct.unpack("!HHHHHH", response[:12])

# check transaction ID matches the one sent
if response_id != transaction_id:
    print("transaction id does not match, aborting mission")
    sys.exit()


# helper function to read a domain name
# handles normal and compressed cases
def read_domain_name(message, position):
    name_parts = []

    while True:
        length = message[position]

        # reached end of name
        if length == 0:
            position += 1
            break

        # if this is a compression case
        if (length & 0xC0) == 0xC0:
            # read pointer value
            pointer = struct.unpack("!H", message[position : position + 2])[0]
            # remove flag bits
            pointer &= 0x3FFF
            # read name from pointer location
            return read_domain_name(message, pointer)[0], position + 2

        # normal case
        position += 1
        name_parts.append(message[position : position + length].decode())
        position += length

    return ".".join(name_parts), position


# print question
print("\nquestion section")
offset = 12
for _ in range(question_count):
    domain_name, offset = read_domain_name(response, offset)
    record_type, record_class = struct.unpack("!HH", response[offset : offset + 4])
    offset += 4

    print(domain_name, "type A, class IN")


# parse a section of resource records
def parse_records(count, section_title, message, position):
    # no records case
    if count == 0:
        return position

    print("\n" + section_title)
    # for all records in section
    for _ in range(count):
        domain_name, position = read_domain_name(message, position)

        record_type, record_class, time_to_live, data_length = struct.unpack(
            "!HHIH", message[position : position + 10]
        )

        position += 10
        # get records
        record_data = message[position : position + data_length]
        position += data_length

        if record_type == 1 and data_length == 4:
            ip_address = ".".join(str(b) for b in record_data)
            print(domain_name, "type A, class IN, addr ", ip_address)
        else:
            print(domain_name, "type", record_type)

    return position


# parse all sections
offset = parse_records(answer_count, "answer section", response, offset)
offset = parse_records(authority_count, "authority section", response, offset)
offset = parse_records(additional_count, "additional section", response, offset)
