import can
import time
import math
import socket

HOST = "127.0.0.1"
PORT = 9000
data_bytes = None

def initialize_can_bus():
    try:
        bus = can.interface.Bus(channel='vcan1', interface='socketcan')
        return bus
    except Exception:
        return None

def extract_primary_header(raw_data):
    spp_header = int.from_bytes(raw_data[0:6], byteorder='big')
    return spp_header

def chunk_data_filed(raw_data):
    data = raw_data[6:]
    chunks = []
    max_data_per_sequence = 8
    if len(data) > max_data_per_sequence:
        for i in range(0, len(data), max_data_per_sequence):
            chunk = data[i:i+max_data_per_sequence]
            chunks.append(chunk)
    else:
        if data:
            chunks.append(data)
    return chunks 

def request_sb_frame(bus, spp_header, blocks):
    global data_bytes  
    to_address = 32
    SB = 4
    from_address = 65
    RQ_type = 0b000
    command = (RQ_type << 7) | (blocks & 0x3f)
    extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
    prefix = 0x00
    counter = (blocks & 0x7f) << 1 | 0x01

    data_bytes = bytearray(8)
    data_bytes[0] = prefix
    data_bytes[1:7] = spp_header.to_bytes(6, byteorder='big')
    data_bytes[7] = counter

    message = can.Message(arbitration_id=extended_id, data=bytes(reversed(data_bytes)), is_extended_id=True)
    try:
        bus.send(message)
    except Exception:
        return None
    return data_bytes


def transfer_sb_frame(bus, raw_data):
    chunks = chunk_data_filed(raw_data)
    try:
        to_address = 32
        SB = 4
        from_address = 65
        pre_command = 0b001

        for index, chunk in enumerate(chunks):
            sequence = index
            command = (pre_command << 7) | (sequence & 0x3f)
            extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
            msg = can.Message(arbitration_id=extended_id, data=chunk, is_extended_id=True)
            try:
                bus.send(msg)
            except can.CanError:
                pass

        status_frame(bus)

    except Exception:
        pass
    return True

def status_frame(bus):
    to_address = 32
    SB = 4
    from_address = 65
    status_type = 0b110
    command = (status_type << 7)
    extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
    message = can.Message(arbitration_id=extended_id, data=b'', is_extended_id=True)
    try:
        bus.send(message)
        return True
    except Exception:
        return False

def calculate_blocks_needed(raw_data):
    L = int.from_bytes(raw_data[4:6], byteorder='big')
    total_bytes = (L + 1)
    blocks = math.ceil(total_bytes / 8)
    blocks = blocks - 1
    return blocks

def abort_frame(bus):
    sending = False
    while True:
        frame = bus.recv(timeout=1.0)
        if frame is None:
            continue
        if not sending and frame.arbitration_id == 0x083083C0:
            sending = True
        if sending:
            to_address = 32
            SB = 4
            from_address = 65
            abort_type = 0b011
            command = (abort_type << 7) | (0x00 & 0x3f)
            extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
            message = can.Message(arbitration_id=extended_id, data=b'', is_extended_id=True)
            try:
                bus.send(message)
                return True
            except Exception:
                return False

def send_request_until_ack(bus, raw_data, max_retries=5, timeout=0.2):
    spp_header = extract_primary_header(raw_data)
    blocks = calculate_blocks_needed(raw_data)

    TO_RADIO = 65
    FROM_OBC = 32
    TYPE_SETBLOCK = 4
    cmd_mask = 0x3FF
    ack_prefix = (0b010 << 7) & cmd_mask  
    block_bits = blocks & 0x3F   
    cmd = ack_prefix | block_bits
    expected_ack_id = (TO_RADIO << 21) | (TYPE_SETBLOCK << 18) | (FROM_OBC << 10) | cmd
    nack_prefix = (0b100 << 7) & cmd_mask
    expected_nack_id = (TO_RADIO << 21) | (TYPE_SETBLOCK << 18) | (FROM_OBC << 10) | nack_prefix

    for attempt in range(1, max_retries + 1):
        request_sb_frame(bus, spp_header, blocks)
        start = time.time()
        while (time.time() - start) < timeout:
            frame = bus.recv(timeout=timeout)
            if frame is None:
                time.sleep(0.01)
                continue
            if frame.arbitration_id == expected_ack_id:
                return True
            if frame.arbitration_id == expected_nack_id:
                return False
        if attempt < max_retries:
            time.sleep(2.0)
    return False

def complete_workflow(bus, raw_data):
    try:

        if not send_request_until_ack(bus, raw_data, max_retries=10, timeout=0.2):
            return False

        transfer_sb_frame(bus, raw_data)
        return True

    except Exception:
        return False

def start_server():
    bus = initialize_can_bus()
    if not bus:
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        
        client_socket, client_address = server_socket.accept()
        
        while True:
            try:
                raw_data = client_socket.recv(40960000)
                if not raw_data:
                    break
                    
                complete_workflow(bus, raw_data)
                
            except Exception:
                break

    except KeyboardInterrupt:
        pass
    except Exception:
        pass
    finally:
        if 'client_socket' in locals():
            client_socket.close()
        if server_socket:
            server_socket.close()
        if bus:
            bus.shutdown()

if __name__ == "__main__":
    start_server()
