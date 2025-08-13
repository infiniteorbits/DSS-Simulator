import can
import time
import math

confirmed_ack_frame_id = None
original_request_blocks = None
tracked_transfer_frames = {}

def is_set_block_request_frame(frame_id):
    """
    Check if frame is a Set Block Request frame
    """
    transfer_type = (frame_id >> 18) & 0x7  
    command = frame_id & 0x3FF              # Extract command 
    frame_type = (command >> 7) & 0x7       # Extract frame type 
    is_set_block = (transfer_type == 4)      
    is_request = (frame_type == 0)         
    
    return is_set_block and is_request

def is_set_block_transfer_frame(frame_id):
    """
    Check if frame is a Set Block Transfer frame
    """
    transfer_type = (frame_id >> 18) & 0x7
    command = frame_id & 0x3FF
    frame_type = (command >> 7) & 0x7
    is_set_block = (transfer_type == 4)      # 100 
    is_transfer = (frame_type == 1)          # 001 
    return is_set_block and is_transfer

def is_status_request_frame(frame_id):
    """
    Check if frame is a Status Request frame
    """
    transfer_type = (frame_id >> 18) & 0x7
    command = frame_id & 0x3FF
    frame_type = (command >> 7) & 0x7
    is_set_block = (transfer_type == 4)      # 100 
    is_status_req = (frame_type == 6)        # 110 
    return is_set_block and is_status_req

def is_abort_frame(frame_id):
    """
    Check if frame is an abort 
    """
    transfer_type = (frame_id >> 18) & 0x7   
    command = frame_id & 0x3FF             
    frame_type = (command >> 7) & 0x7        
    is_set_block = (transfer_type == 4)      # 100 
    is_abort = (frame_type == 3)             # 011 
    return is_set_block and is_abort

def extract_blocks_from_request_frame(frame_id):
    """
    Extract number of blocks from Set Block Request frame
    """
    if not is_set_block_request_frame(frame_id):
        return None
        
    command = frame_id & 0x3FF
    blocks_minus_one = command & 0x3F        
    blocks = blocks_minus_one + 1         
    return blocks

def extract_block_index_from_transfer(frame_id):
    """
    Extract block index from Set Block Transfer frame
    """
    if not is_set_block_transfer_frame(frame_id):
        return None
        
    command = frame_id & 0x3FF
    block_index = command & 0x3F              
    return block_index

def send_ack_response(bus, received_frame):

    try:
    
        received_to_addr = (received_frame.arbitration_id >> 21) & 0xFF
        received_from_addr = (received_frame.arbitration_id >> 10) & 0xFF
        to_address = received_from_addr      
        from_address = received_to_addr     
        transfer_type = 4                   
        # ACK command structure
        ack_frame_type = (0b010 << 7)       
        original_command = received_frame.arbitration_id & 0x3FF
        command_bits = original_command & 0x7F 
        ack_command = ack_frame_type | command_bits
    
        ack_extended_id = (to_address << 21) | (transfer_type << 18) | (from_address << 10) | ack_command
        
        copied_data = received_frame.data  
        # Send ACK message
        ack_message = can.Message(
            arbitration_id=ack_extended_id,
            data=copied_data,
            is_extended_id=True
        )
        bus.send(ack_message)
        print(f"ACK sent successfully")
        return True
        
    except Exception as e:
        print(f" Error sending ACK: {e}")
        return False

def send_abort_acknowledge_response(bus, received_frame):
    
    try:
        received_to_addr = (received_frame.arbitration_id >> 21) & 0xFF
        received_from_addr = (received_frame.arbitration_id >> 10) & 0xFF 
        to_address = received_from_addr     
        from_address = received_to_addr     
        transfer_type = 4                   
        ack_frame_type = (0b010 << 7)       # ACK = 010 
        original_command = received_frame.arbitration_id & 0x3FF
        command_bits = original_command & 0x7F 
        abort_ack_command = ack_frame_type | command_bits
        
      
        abort_ack_extended_id = (to_address << 21) | (transfer_type << 18) | (from_address << 10) | abort_ack_command
        abort_ack_message = can.Message( arbitration_id=abort_ack_extended_id,data=b'',  is_extended_id=True)
        bus.send(abort_ack_message)
        print(f" ABort ack sent: 0x{abort_ack_extended_id:08X} [0] #")
        return True
        
    except Exception as e:
        print(f" Error sending Abort Acknowledge: {e}")
        return False

def reset_session_state():

    global original_request_blocks, tracked_transfer_frames
    
    original_request_blocks = None
    tracked_transfer_frames = {}

def generate_report_frame(bus, tracked_frames, expected_blocks):

    try:
        to_address = 32        # OBC
        from_address = 65      # Radio
        transfer_type = 4      # Set Block typ
        received_blocks = set(tracked_frames.keys())
        expected_block_set = set(range(expected_blocks))
        all_blocks_received = received_blocks == expected_block_set        
        report_frame_type = (0b111 << 7)     # Report = 111 
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
        
        if len(received_blocks) < expected_blocks:
            missing = expected_block_set - received_blocks
            print(f" Missing blocks: {sorted(missing)}")
        
        report_message = can.Message(
            arbitration_id=extended_id,
            data=bytes(bitmap_bytes),
            is_extended_id=True
        )
        bus.send(report_message)
        print(f" Report frame sent: 0x{extended_id:08X} with {len(bitmap_bytes)} bytes: {bitmap_bytes.hex().upper()}")
        return True
        
    except Exception as e:
        print(f" Error generating report frame: {e}")
        return False

def process_single_set_block_session(bus, request_frame, session_timeout=5.0):
    global original_request_blocks, tracked_transfer_frames
    tracked_transfer_frames = {}
    session_start = time.time()

    try:

        original_request_blocks = extract_blocks_from_request_frame(request_frame.arbitration_id)
        if original_request_blocks is None or original_request_blocks <= 0:
            print(f" Invalid block count from request")
            return False
        
        print(f" Expected blocks: {original_request_blocks}")
    
        ack_success = send_ack_response(bus, request_frame)
        if not ack_success:
            print(f" Failed to send ACK")
            return False
        
        print(f" Waiting for transfer frames and Status Request")
        
        while (time.time() - session_start) < session_timeout:
            frame = bus.recv(timeout=0.01) 
            
            if frame is None:
                continue
            
            if is_set_block_request_frame(frame.arbitration_id):
                print(f" New Set Block Request received - completing current session first")
                break
            
            elif is_set_block_transfer_frame(frame.arbitration_id):
                block_index = extract_block_index_from_transfer(frame.arbitration_id)
                
                if block_index is not None and 0 <= block_index < original_request_blocks:
                  
                    if block_index not in tracked_transfer_frames:
                        tracked_transfer_frames[block_index] = {
                            'frame_id': frame.arbitration_id,
                            'data': frame.data,
                            'timestamp': time.time()
                        }
                        
                        print(f" Transfer frame received - Block {block_index}: 0x{frame.arbitration_id:08X}")
                        print(f"   Data: {frame.data.hex()}")
                        print(f"   Progress: {len(tracked_transfer_frames)}/{original_request_blocks}")
                        
                        # Check if all blocks received
                        if len(tracked_transfer_frames) == original_request_blocks:
                            print(f" All blocks received!")
                    else:
                        print(f" Duplicate block {block_index} received")
                else:
                    print(f"Invalid block index {block_index} for {original_request_blocks} blocks")
       
            elif is_status_request_frame(frame.arbitration_id):
                print(f"Status Request received: 0x{frame.arbitration_id:08X}")
                print(f"   Data: {frame.data.hex()}")
                
                report_success = generate_report_frame(bus, tracked_transfer_frames, original_request_blocks)
                
                if report_success:
                    
                    abort_timeout = 1.0 
                    abort_start = time.time()
                    
                    while (time.time() - abort_start) < abort_timeout:
                        abort_frame = bus.recv(timeout=0.02)
                        
                        if abort_frame is None:
                            continue
                   
                        if is_abort_frame(abort_frame.arbitration_id):
                            print(f"Abort frame received: 0x{abort_frame.arbitration_id:08X}")
                            print(f"   Transfer type: {(abort_frame.arbitration_id >> 18) & 0x7} (100)")
                            print(f"   Frame type: {((abort_frame.arbitration_id & 0x3FF) >> 7) & 0x7} (011)")
                            
                            abort_ack_success = send_abort_acknowledge_response(bus, abort_frame)
                            
                            if abort_ack_success:
                                print(f" Set Block session completed successfully!")
                                reset_session_state()
                                return True
                            else:
                                print(f" Failed to send abort acknowledge")
                                reset_session_state()
                                return False
                        
                        
                        elif is_set_block_request_frame(abort_frame.arbitration_id):
                            print(f" New request received during abort wait - ending current session")
                            reset_session_state()
                            return False 
                    
                    print(f" Timeout waiting for abort frame after report")
                    reset_session_state()
                    return False
                else:
                    print(f" Failed to send Report frame")
                    reset_session_state()
                    return False
            
            
            elif is_abort_frame(frame.arbitration_id):
                print(f" Unexpected abort frame received: 0x{frame.arbitration_id:08X}")
                send_abort_acknowledge_response(bus, frame)
                reset_session_state()
                return False
        
        print(f" Session timeout waiting for Status Request")
        reset_session_state()
        return False
        
    except Exception as e:
        print(f" Error in Set Block session: {e}")
        reset_session_state()
        return False

def continuous_set_block_converter(bus):
    session_count = 0
    try:
        while True:
            
            frame = bus.recv(timeout=0.1)  
            
            if frame is None:
                continue
            
            if is_set_block_request_frame(frame.arbitration_id):
                session_count += 1
                session_success = process_single_set_block_session(bus, frame, session_timeout=5.0)
                
                if session_success:
                    print(f" Session #{session_count} completed successfully!")
                else:
                    print(f" Session #{session_count} failed ")
                
            else:
                transfer_type = (frame.arbitration_id >> 18) & 0x7
                if transfer_type == 4:
                    command = frame.arbitration_id & 0x3FF
                    frame_type = (command >> 7) & 0x7
                    print(f" Other Set Block frame: 0x{frame.arbitration_id:08X} (type={frame_type:03b})")
                
    except KeyboardInterrupt:
        print(f"\n Continuous converter stopped by user")
        print(f" Total sessions processed: {session_count}")
    except Exception as e:
        print(f" Error in continuous converter: {e}")
        print(f" Total sessions processed: {session_count}")

if __name__ == "__main__":
    # Initialize CAN bus
    bus = can.interface.Bus(
        channel='vcan1',
        interface='socketcan'
    )
    continuous_set_block_converter(bus)
