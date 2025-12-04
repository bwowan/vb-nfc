import sys
import smartcard.scard
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection

import do_comm
import card_data
import do_prompt


############################################################################################################
#read all card info
def fnReadMifare1k(dump: card_data.dumpMifare_1k, connection: CardConnection, key: card_data.key) -> bool:
    totalFailCount    = 0
    totalBlocksRead   = 0
    try:
        for iSector, sector in enumerate(dump.sectors):
            nBlock0 = iSector * card_data.MIFARE_1K_blocks_per_sector
            if not do_comm.fnLoadKey(connection, key.keyData):
                sector.status = card_data.status.S_KEY_ERROR
                totalFailCount += 1
            else:
                if not do_comm.fnSelectBlock(connection, nBlock0, key.keyType.value):
                    sector.status = card_data.status.S_AUTH_ERROR
                    totalFailCount += 1
                else:
                    failCount = 0
                    sector.status = card_data.status.S_OK
                    for iBlock, block in enumerate(sector.blocks):
                        readOk, data = do_comm.fnReadBlock(connection, nBlock0 + iBlock, card_data.MIFARE_1K_bytes_per_block)
                        if readOk:
                            block.data = data
                            block.status = card_data.status.S_OK
                            totalBlocksRead += 1
                            if (iBlock + 1) == card_data.MIFARE_1K_blocks_per_sector:
                                sector.trailer.processLastBlock(block.data)   
                        else:
                            failCount += 1
                            totalFailCount += 1
                            block.status = card_data.status.S_READ_ERROR
                    if failCount != 0:
                        sector.status = card_data.status.S_READ_ERROR
                        
        dump.head.read(dump.sectors[0].blocks[0])
    except Exception as e:
        dump.status = card_data.status.S_READ_ERROR
        print(f"dump error: {e}\n")

    print("read {totalBlocksRead} blocks")
    return totalBlocksRead > 0


############################################################################################################
def fnWriteBlock(nSector: int, nBlock: int, blockData: list[bytes], key: list[bytes]):
    Result = False
    try:
        request = CardRequest(timeout=10)
        service = request.waitforcard()
        connection = service.connection
        connection.connect(mode=smartcard.scard.SCARD_SHARE_EXCLUSIVE, disposition=smartcard.scard.SCARD_UNPOWER_CARD)        
        try:
            if do_comm.fnLoadKey(connection, key):
                nBlock0 = nSector * card_data.MIFARE_1K_blocks_per_sector
                if do_comm.fnSelectBlock(connection, nBlock0, "B"):
                    if do_comm.fnWriteBlock(connection, nBlock0 + nBlock, blockData):
                        print(f"Successfully wrote block {nSector}:{nBlock}.")
                        Result = True
        finally:
            connection.disconnect()
    except Exception as e:
        sys.stdout.write(f"Error writing block: {e}")
    return Result


def fnWriteBlockStr(nSector: int, nBlock: int, blockDataStr: str, key: list[bytes]) -> bool:
    return fnWriteBlock(nSector, nBlock, list(blockDataStr.encode()), key)

#==============================================================================================
def fnWrite(writeData: do_prompt.PromptAnswer_ForWrite, key:card_data.key) -> bool:
    """
    Write data to a MIFARE 1K card.
    
    This function writes data blocks to the card, handling sector authentication
    automatically when entering a new sector. The starting block is determined
    based on the address type specified in writeData.
    
    Args:
        writeData: Contains the data to write, address type (block/sector), and
                   sector/block numbers indicating where to start writing.
        key: Authentication key object containing key data and key type (A/B).
    
    Returns:
        bool: True if the write operation was successful, False otherwise.
    """
    # Validate data length - must be a multiple of block size (16 bytes)
    dataLen = len(writeData.data)
    if dataLen == 0  or  dataLen % card_data.MIFARE_1K_bytes_per_block != 0:
        print(f"Data length {dataLen} is not valid - must be multiple of {card_data.MIFARE_1K_bytes_per_block}")
        return False
    
    # Determine starting block based on address type
    # For A_BLOCK: start at specific block within sector
    # For A_SECTOR: start at first block of the sector
    nStartBlock = 1 #otherwise - first writable block of first sector
    match writeData.address:
        case do_prompt.writeAddress.A_BLOCK : nStartBlock = writeData.nSector * card_data.MIFARE_1K_blocks_per_sector + writeData.nBlock
        case do_prompt.writeAddress.A_SECTOR: nStartBlock = writeData.nSector * card_data.MIFARE_1K_blocks_per_sector

    Result = False
    try:
        request = CardRequest(timeout=10)
        service = request.waitforcard()
        connection = service.connection
        connection.connect(mode=smartcard.scard.SCARD_SHARE_EXCLUSIVE, disposition=smartcard.scard.SCARD_UNPOWER_CARD)        
        try:
            # Calculate absolute block number from start of card
            nStartBlock = writeData.nSector * card_data.MIFARE_1K_blocks_per_sector + writeData.nBlock #сквозной номер от начала карты
            # Track if we're entering a new sector (requires authentication)
            startNewSector = True
            # Write each block of data
            for i in range(dataLen // card_data.MIFARE_1K_bytes_per_block):
                # Calculate absolute block number across entire card
                nBlockThrowCard = nStartBlock + i
                # Calculate which sector this block belongs to
                nSector = nBlockThrowCard // card_data.MIFARE_1K_blocks_per_sector
                # Calculate block number within the sector (0-3)
                nBlockInsideSector = nBlockThrowCard % card_data.MIFARE_1K_blocks_per_sector
                # If we're continuing in the same sector, no need to re-authenticate
                isOk = not startNewSector
                # If entering a new sector, authenticate with the key
                if startNewSector:
                    # Get first block of the sector (block 0 of the sector)
                    nBlock0 = nSector * card_data.MIFARE_1K_blocks_per_sector
                    # Load key and authenticate to the sector
                    isOk = do_comm.fnLoadKey(connection, key.keyData) and do_comm.fnSelectBlock(connection, nBlock0, key.keyType.value)
                # If authentication succeeded (or not needed), write the block
                if isOk:
                    # Extract block data from the write buffer
                    blockData = writeData.data[i * card_data.MIFARE_1K_bytes_per_block:(i + 1) * card_data.MIFARE_1K_bytes_per_block]
                    # Write the block to the card
                    if do_comm.fnWriteBlock(connection, nBlockThrowCard, blockData):
                        print(f"Successfully wrote block {nSector}:{nBlockInsideSector} --> {do_comm.bytes2str(blockData)}") 
                # Check if next iteration will be in a new sector (if current block is last in sector)
                startNewSector = nBlockInsideSector == (card_data.MIFARE_1K_blocks_per_sector - 1)
        finally:
            # Always disconnect from the card
            connection.disconnect()
    except Exception as e:
        sys.stdout.write(f"Error writing block: {e}")
    return Result
