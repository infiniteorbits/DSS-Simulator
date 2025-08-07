import can
import time
import math
import sys
data_bytes = None


def extract_primary_header(raw_data):
    """
    Extracts the primary header from the given data.
    
    Args:
        raw_data (bytes): The binary data containing the primary header.
        
    Returns:
        int: The extracted primary header as an integer.
    """ 
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
    """
    Sends a Set Block frame request to start sending data.

    Args:
        spp_header (int): The SPP header value as integer.
        blocks (int): Number of blocks
        
    Returns:
        can.Message: The CAN message that was sent.
    """ 
    global data_bytes  
    to_address = 32        # OBC address
    SB = 4                 # Set block
    from_address = 65      # radio address
    RQ_type = 0b000        # Set Block Request 
    command = (RQ_type << 7) | (blocks & 0x3f) 
    
    # Build extended ID
    extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
    prefix = 0x00          # Prefix start addrss
    counter = (blocks&0x7f)<<1|0x01
 
    data_bytes = bytearray(8)
    data_bytes[0] = prefix
    data_bytes[1:7] = spp_header.to_bytes(6, byteorder='big')
    data_bytes[7] = counter
   
    message = can.Message(arbitration_id=extended_id, data=bytes(reversed(data_bytes)), is_extended_id=True)
    try:
        bus.send(message)
    except Exception as e:
        print(f"Error sending CAN message: {e}")
        return None
    return data_bytes


def Transfer_SBFrame(bus, raw_data):
    chunks = chunk_data_filed(raw_data)
    try:
        print('Start sending data')
        
        # Configuration
        to_address = 32        # OBC address
        SB = 4                 # Set block
        from_address = 65      # radio address
        pre_command = 0b001    # Transfer type 

        # Send all data chunks
        for index, chunk in enumerate(chunks):
            sequence = index
            
            if len(chunk) < 8:
                padded_chunk = chunk + b'\x00' * (8 - len(chunk))
                command = (pre_command << 7) | (sequence & 0x3f)
                extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
                msg = can.Message(arbitration_id=extended_id, data=padded_chunk, is_extended_id=True)
            else:
                command = (pre_command << 7) | (sequence & 0x3f)
                extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
                msg = can.Message(arbitration_id=extended_id, data=chunk, is_extended_id=True)
            
            try:
                bus.send(msg)
                print(f"Sent chunk {index + 1}/{len(chunks)}")
            except can.CanError as e:
                print(f"Failed to send chunk {index}: {e}")
        
        # Send status frame
        print("All data sent. Sending status frame...")
        status_frame(bus)
                
    except Exception as e:
        print(f"Error in transfer: {e}")


def status_frame(bus):
    to_address = 32        # OBC address
    SB = 4                 # Set block
    from_address = 65      # radio address
    status_type = 0b110    # Status Request type
    command = (status_type << 7)  
    
   
    extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
    
    message = can.Message(arbitration_id=extended_id, data=b'', is_extended_id=True)
    try:
        bus.send(message)
        print("Status frame sent successfully")
    except Exception as e:
        print(f"Error sending CAN message: {e}")


def calculate_blocks_needed(raw_data):
    """
    Calculate number of blocks needed based on CCSDS header.
    
    Args:
        raw_data (bytes): The complete CCSDS packet
        
    Returns:
        int: Number of 8-byte blocks needed
    """
   
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
            print('Received report frame')
            sending = True
            
        if sending:
            to_address = 32        # OBC address
            SB = 4                 # Set block type
            from_address = 65      # radio address
            abort_type = 0b011     
            command = (abort_type << 7) | (0x00 & 0x3f) 
            extended_id = (to_address << 21) | (SB << 18) | (from_address << 10) | command
            message = can.Message(arbitration_id=extended_id, data=b'', is_extended_id=True)
            try:
                bus.send(message)
                print(f"Abort frame sent successfully, command=0x{command:03X}, ID=0x{extended_id:08X}")
                break
            except Exception as e:
                print(f"Error sending Abort frame: {e}")


def send_request_until_ack(bus, raw_data, max_retries=5, timeout=0.200):


    spp_header = extract_primary_header(raw_data)
    blocks = calculate_blocks_needed(raw_data)

    TO_RADIO = 65
    FROM_OBC = 32
    TYPE_SETBLOCK = 4
    
    cmd_mask = 0x3FF
    
   
    ack_prefix = (0b010 << 7) & cmd_mask  #
    block_bits = blocks & 0x3F   
    cmd = ack_prefix | block_bits

    expected_ack_id = (TO_RADIO << 21) | (TYPE_SETBLOCK << 18) | (FROM_OBC << 10) | cmd
    
    nack_prefix = (0b100 << 7) & cmd_mask
    expected_nack_id = (TO_RADIO << 21) | (TYPE_SETBLOCK << 18) | (FROM_OBC << 10) | nack_prefix

    # Main retry loop
    for attempt in range(1, max_retries + 1):
        print(f"Attempt {attempt}/{max_retries}")
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

        print("Timeout, no ACK retrying…")
        
        if attempt < max_retries:
            retry_delay = 2.0
           
            time.sleep(retry_delay)

    print("Retry budget exhausted - giving up")
    return False


if __name__ == "__main__":
    bus = can.interface.Bus(
        channel='vcan1',        
        interface='socketcan')  

    raw_data = bytes.fromhex('1814c00200182f03060000110304060f051011010708090a0b0c0d0e02bdcf')
    spp_header = extract_primary_header(raw_data)
    blocks = calculate_blocks_needed(raw_data)
    print(f"Blocks needed: {blocks}")
    
    # Send request and wait for ACK
    if not send_request_until_ack(bus, raw_data, max_retries=10, timeout=0.2):
        print("Set-Block session could not be started")
        sys.exit(1)
    
    # Proceed directly to data transfer after ACK
    Transfer_SBFrame(bus, raw_data)
    time.sleep(1)
    abort_frame(bus)
