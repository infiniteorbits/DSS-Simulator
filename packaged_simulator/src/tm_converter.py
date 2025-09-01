import can
import time
import math
import socket

tracked_transfer_frames = {}
session_active = False
captured_sessions = []
SOCKET_HOST = "127.0.0.1"
SOCKET_PORT = 8091

def is_set_block_request_frame(frame_id):
    base_pattern = 0x08308000
    mask = 0xFFFFFFC0  
    masked_id = frame_id & mask
    return masked_id == base_pattern

def is_set_block_transfer_frame(frame_id):
    base_pattern = 0x08308080
    mask = 0xFFFFFFC0
    masked_id = frame_id & mask
    return masked_id == base_pattern

def is_status_request_frame(frame_id):
    return frame_id == 0x08308300

def is_abort_frame(frame_id):
    return frame_id == 0x08308180

def extract_spp_header_from_request(frame_data):
    try:
        original_data = bytes(reversed(frame_data))
        spp_header_bytes = original_data[1:7]
        return spp_header_bytes
    except Exception as e:
        return None, None

def extract_block_index_from_transfer(frame_id):
    if not is_set_block_transfer_frame(frame_id):
        return None      
    command = frame_id & 0x3FF
    block_index = command & 0x3F 
    return block_index

def reconstruct_original_data(spp_header_bytes, transfer_frames):
    try:
        reconstructed_data = bytearray(spp_header_bytes)
        sorted_blocks = sorted(transfer_frames.keys())
        
        for block_index in sorted_blocks:
            frame_data = transfer_frames[block_index]['data']
            reconstructed_data.extend(frame_data)
        
        return bytes(reconstructed_data)
    except Exception as e:
        return None

def send_tm_packet_over_socket(tm_packet_data, transfer_frames):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        
        sock.connect((SOCKET_HOST, SOCKET_PORT))
        sock.sendall(tm_packet_data)
        sock.close()   
        return True
        
    except Exception as e:
        return False

def send_ack_response(bus, received_frame):
    global session_active, tracked_transfer_frames
    
    try:
        received_to_addr = (received_frame.arbitration_id >> 21) & 0xFF
        received_from_addr = (received_frame.arbitration_id >> 10) & 0xFF
        to_address = received_from_addr
        from_address = received_to_addr
        transfer_type = 4
        ack_frame_type = (0b010 << 7)
        original_command = received_frame.arbitration_id & 0x3FF
        command_bits = original_command & 0x7F
        ack_command = ack_frame_type | command_bits
        ack_extended_id = (to_address << 21) | (transfer_type << 18) | (from_address << 10) | ack_command
        ack_message = can.Message(
            arbitration_id=ack_extended_id,
            data=received_frame.data,
            is_extended_id=True
        )
        
        bus.send(ack_message)
        session_active = True
        tracked_transfer_frames = {}
        return True
        
    except Exception as e:
        return False

def send_standardized_abort_acknowledge_response(bus, received_frame):
    try:
        received_to_addr = (received_frame.arbitration_id >> 21) & 0xFF
        received_from_addr = (received_frame.arbitration_id >> 10) & 0xFF
        to_address = received_from_addr
        from_address = received_to_addr
        transfer_type = 4
        ack_frame_type = (0b010 << 7)
        original_command = received_frame.arbitration_id & 0x3FF
        command_bits = original_command & 0x7F
        abort_ack_command = ack_frame_type | command_bits
        abort_ack_extended_id = (to_address << 21) | (transfer_type << 18) | (from_address << 10) | abort_ack_command
        abort_ack_message = can.Message(
            arbitration_id=abort_ack_extended_id,
            data=b'',
            is_extended_id=True
        )
        bus.send(abort_ack_message)
        return True
        
    except Exception as e:
        return False

def generate_report_frame(bus, tracked_frames):
    try:
        to_address = 32
        from_address = 65
        transfer_type = 4
        
        if not tracked_frames:
            expected_blocks = 1
        else:
            max_block_index = max(tracked_frames.keys())
            expected_blocks = max_block_index + 1
        
        received_blocks = set(tracked_frames.keys())
        expected_block_set = set(range(expected_blocks))
        all_blocks_received = received_blocks == expected_block_set
        report_frame_type = (0b111 << 7)
        done_bit = (1 << 6) if all_blocks_received else 0
        report_command = report_frame_type | done_bit
        extended_id = (to_address << 21) | (transfer_type << 18) | (from_address << 10) | report_command
        bitmap_bytes_needed = math.ceil(expected_blocks / 8)
        bitmap_bytes = bytearray(bitmap_bytes_needed)
        for block_num in received_blocks:
            if block_num < expected_blocks:
                byte_index = block_num // 8
                bit_index = block_num % 8
                if byte_index < bitmap_bytes_needed:
                    bitmap_bytes[byte_index] |= (1 << bit_index)
        
        if expected_blocks % 8 != 0:
            last_byte_bits = expected_blocks % 8
            mask = (1 << last_byte_bits) - 1
            bitmap_bytes[-1] &= mask
        
        report_message = can.Message(
            arbitration_id=extended_id,
            data=bytes(bitmap_bytes),
            is_extended_id=True
        )
        
        bus.send(report_message)
        return True
        
    except Exception as e:
        return False

def clear_tracked_frames():
    global tracked_transfer_frames, session_active
    tracked_transfer_frames = {}
    session_active = False

def process_complete_session(request_frame_data, transfer_frames):
    spp_header_bytes = extract_spp_header_from_request(request_frame_data)
    
    if spp_header_bytes is None:
        return   
    tm_packet_data = reconstruct_original_data(spp_header_bytes, transfer_frames)  
    if tm_packet_data is None:
        return  
    send_tm_packet_over_socket(tm_packet_data, transfer_frames)
    captured_sessions.append({
        'original_data': tm_packet_data,
        'transfer_frames': transfer_frames,
    })

def process_frame(bus, frame):
    global tracked_transfer_frames, session_active
    
    if not hasattr(process_frame, 'current_request_data'):
        process_frame.current_request_data = None
    
    if is_set_block_request_frame(frame.arbitration_id):
        process_frame.current_request_data = frame.data
        
        if session_active:
            clear_tracked_frames()
        
        send_ack_response(bus, frame)
        return
    if is_set_block_transfer_frame(frame.arbitration_id):
        if session_active:
            block_index = extract_block_index_from_transfer(frame.arbitration_id)
            
            if block_index is not None:
                tracked_transfer_frames[block_index] = {
                    'frame_id': frame.arbitration_id,
                    'data': frame.data,
                }
        return
    
    if is_status_request_frame(frame.arbitration_id):
        if session_active:
            if process_frame.current_request_data and tracked_transfer_frames:
                process_complete_session(process_frame.current_request_data, tracked_transfer_frames)
            
            generate_report_frame(bus, tracked_transfer_frames)
            clear_tracked_frames()
        return
    
    if is_abort_frame(frame.arbitration_id):
        if session_active and tracked_transfer_frames:
            if process_frame.current_request_data:
                process_complete_session(process_frame.current_request_data, tracked_transfer_frames)
            
            generate_report_frame(bus, tracked_transfer_frames)
        
        send_standardized_abort_acknowledge_response(bus, frame)
        clear_tracked_frames()
        return

def continuous_transfer_tracker(bus):
    try:
        while True:
            frame = bus.recv(timeout=0.001)
            
            if frame is None:
                continue   
            if (is_set_block_transfer_frame(frame.arbitration_id) or 
                is_status_request_frame(frame.arbitration_id) or 
                is_set_block_request_frame(frame.arbitration_id) or 
                is_abort_frame(frame.arbitration_id)):
                process_frame(bus, frame)
                
    except KeyboardInterrupt:
        pass
    except Exception as e:
        pass

if __name__ == "__main__":
    bus = can.interface.Bus(
        channel='vcan1',
        interface='socketcan'
    )
    continuous_transfer_tracker(bus)
