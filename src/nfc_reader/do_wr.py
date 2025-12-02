import sys
import smartcard.scard
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection

import do_comm
import card_data


############################################################################################################
#read all card info
def fnReadMifare1k(dump: card_data.dumpMifare_1k, connection: CardConnection, key = card_data.MIFARE_1K_default_key) -> bool:
    totalFailCount    = 0
    totalBlocksRead   = 0
    try:
        for iSector, sector in enumerate(dump.sectors):
            nBlock0 = iSector * card_data.MIFARE_1K_blocks_per_sector
            if not do_comm.fnLoadKey(connection, key):
                sector.status = card_data.status.S_KEY_ERROR
                totalFailCount += 1
            else:
                if not do_comm.fnSelectBlock(connection, nBlock0):
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
        sys.stdout.write(f"dump error: {e}\n")

    sys.stdout.write(f"\nread {totalBlocksRead} blocks\n")
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
                if do_comm.fnSelectBlock(connection, nBlock0):
                    if do_comm.fnWriteBlock(connection, nBlock0 + nBlock, blockData):
                        sys.stdout.write(f"Successfully wrote block {nSector}:{nBlock}.")
                        Result = True
        finally:
            connection.disconnect()
    except Exception as e:
        sys.stdout.write(f"Error writing block: {e}")
    return Result


def fnWriteBlockStr(nSector: int, nBlock: int, blockDataStr: str, key: list[bytes]):
    fnWriteBlock(nSector, nBlock, list(blockDataStr.encode()), key)