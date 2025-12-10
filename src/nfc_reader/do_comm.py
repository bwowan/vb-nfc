from pluggy import Result
from smartcard.CardConnection import CardConnection

def bytes2str(b) -> str:
    return "[" + " ".join(f"{ch:02X}" for ch in b) + "]"


def fnDoTransmit(connection, data: list[bytes]) -> (bool, list[bytes]):
    """
    Send an APDU (Application Protocol Data Unit) command to the NFC card.
    
    This function transmits a command to the card via the smartcard library and
    checks the response status. APDU commands follow the ISO 7816 standard format.
    
    Args:
        connection: CardConnection object from smartcard library, representing
                   an active connection to the NFC card.
        Key: List of bytes representing the APDU command. The APDU format is:
             [CLA, INS, P1, P2, Lc, Data..., Le]
             
             Where:
             - CLA (Class): Command class byte, typically 0xFF for proprietary
                           commands (escape class for PC/SC readers)
             - INS (Instruction): Instruction byte specifying the operation
             - P1 (Parameter 1): First parameter byte
             - P2 (Parameter 2): Second parameter byte
             - Lc (Length of Command data): Number of data bytes to follow
             - Data: Variable-length command data (if Lc > 0)
             - Le (Length of Expected response): Expected number of response bytes
    
    Returns:
        tuple: (True, response_data) if command succeeded (SW1=0x90, SW2=0x00),
               False otherwise.
               
    Note:
        Status words (SW1, SW2) indicate command result:
        - 0x9000: Success (SW1=0x90, SW2=0x00)
        - Other values indicate various error conditions
    """
    try:
        # Transmit APDU command to card and receive response
        # response: data bytes returned by the card
        # sw1, sw2: status words indicating command result
        response, sw1, sw2 = connection.transmit(data)
        # Check for success status (0x9000 = OK)
        if (sw1 == 0x90) and (sw2 == 0x00):
            return True, response
    except Exception as e:
        print(f"transmit error: {e}")
    return False, None


def fnLoadKey(connection: CardConnection, keyData: list[bytes]) -> bool:
    """
    Load authentication key into the reader's volatile memory.
    
    This command stores the key in the reader's temporary memory for subsequent
    authentication operations. The key is not stored permanently on the card.
    
    APDU command format: [0xFF, 0x82, 0x00, 0x00, Lc, KeyData...]
    - 0xFF: CLA (escape class for PC/SC)
    - 0x82: INS (LOAD KEYS instruction)
    - 0x00: P1 (Key structure - 0x00 = volatile memory)
    - 0x00: P2 (Key number/slot - 0x00 = first slot)
    - Lc: Length of key data (typically 6 bytes for MIFARE)
    - KeyData: The actual key bytes to load
    """
    # APDU: [CLA, INS, P1, P2, Lc, KeyData...]
    Result, _ = fnDoTransmit(connection, [0xFF, 0x82, 0x00, 0x00, len(keyData)] + list(keyData)) 
    if not Result:
        print(f"fail to load key: {bytes2str(keyData)}")
    return Result


def fnSelectBlock(connection: CardConnection, nBlockThrowCard: int, keyTypeAB: str) -> bool:
    """
    Authenticate to a specific block/sector on the MIFARE card.
    
    This command performs authentication using a previously loaded key to gain
    access to a sector. After successful authentication, read/write operations
    are allowed for that sector.
    
    APDU command format: [0xFF, 0x86, 0x00, 0x00, 0x05, KeyType, KeyStruct, BlockAddr, 0x60, 0x00]
    - 0xFF: CLA (escape class for PC/SC)
    - 0x86: INS (PERFORM SECURITY OPERATION)
    - 0x00: P1 (not used, set to 0)
    - 0x00: P2 (not used, set to 0)
    - 0x05: Lc (length of command data = 5 bytes)
    - KeyType: 0x00 = Key A, 0x01 = Key B
    - KeyStruct: 0x00 = Key stored in volatile memory (from fnLoadKey)
    - BlockAddr: Absolute block number across entire card (0-63 for MIFARE 1K)
    - 0x60: Authentication mode (MIFARE authentication)
    - 0x00: Additional parameter (not used)
    
    Args:
        connection: Active card connection
        nBlockThrowCard: Absolute block number (0-63 for MIFARE 1K)
        keyTypeAB: 'A' or 'B' to specify which key type to use
    
    Returns:
        bool: True if authentication succeeded, False otherwise
    """
    # Determine key type: 0x00 for Key A, 0x01 for Key B
    keyID = 0x00 if keyTypeAB.upper() == 'A' else 0x01
    # APDU: [CLA, INS, P1, P2, Lc, KeyType, KeyStruct, BlockAddr, AuthMode, Param]

    Result, _ = fnDoTransmit(connection, [0xFF, 0x86, 0x00, 0x00, 0x05, keyID, 0x00, nBlockThrowCard, 0x60, 0x00])
    if not Result:    
        print(f"Authentication failed by key{keyTypeAB} for block:{nBlockThrowCard//4}:{nBlockThrowCard%4}")
    return Result


def fnWriteBlock(connection: CardConnection, nBlockThrowCard: int, data: list[bytes]) -> bool:
    """
    Write data to a block on the MIFARE card.
    
    This command writes data to a specific block. The sector containing the block
    must be authenticated first using fnSelectBlock().
    
    APDU command format: [0xFF, 0xD6, 0x00, BlockAddr, Lc, Data...]
    - 0xFF: CLA (escape class for PC/SC)
    - 0xD6: INS (UPDATE BINARY instruction - write data)
    - 0x00: P1 (not used, set to 0)
    - BlockAddr: Absolute block number across entire card (0-63 for MIFARE 1K)
    - Lc: Length of data to write (typically 16 bytes for MIFARE blocks)
    - Data: The actual data bytes to write to the block
    
    Args:
        connection: Active card connection (sector must be authenticated)
        nBlockThrowCard: Absolute block number (0-63 for MIFARE 1K)
        data: List of bytes to write (must be 16 bytes for MIFARE 1K)
    
    Returns:
        bool: True if write succeeded, False otherwise
    """
    # APDU: [CLA, INS, P1, BlockAddr, Lc, Data...]
    Result, _ = fnDoTransmit(connection, [0xFF, 0xD6, 0x00, nBlockThrowCard, len(data)] + data)
    if not Result:
        print(f"fail to write block: {nBlockThrowCard//4}:{nBlockThrowCard%4}")
    return Result

def fnReadBlock(connection: CardConnection, nBlockThrowCard: int):
    """
    Read data from a block on the MIFARE card.
    
    This command reads data from a specific block. The sector containing the block
    must be authenticated first using fnSelectBlock().
    
    APDU command format: [0xFF, 0xB0, 0x00, BlockAddr, Le]
    - 0xFF: CLA (escape class for PC/SC)
    - 0xB0: INS (READ BINARY instruction - read data)
    - 0x00: P1 (not used, set to 0)
    - BlockAddr: Absolute block number across entire card (0-63 for MIFARE 1K)
    - Le: Expected length of response data (0x10 = 16 bytes for MIFARE blocks)
    
    Args:
        connection: Active card connection (sector must be authenticated)
        nBlockThrowCard: Absolute block number (0-63 for MIFARE 1K)
        count: Number of bytes to read (default 0x10 = 16 bytes for MIFARE 1K)
    
    Returns: tuple: (True, response_data) if read succeeded, (False, None) otherwise
    """
    # APDU: [CLA, INS, P1, BlockAddr, Length]
    return fnDoTransmit(connection, [0xFF, 0xB0, 0x00, nBlockThrowCard])
