import sys
import smartcard.util
from enum import Enum
from smartcard.ATR import ATR

from smartcard.CardConnection import CardConnection

import do_comm

# MIFARE 1K constants
MIFARE_1K_blocks_per_sector = 4
MIFARE_1K_total_sectors     = 16
MIFARE_1K_bytes_per_block   = 16
MIFARE_1K_bytes_per_key     = 6
MIFARE_1K_default_key : list[bytes] = [0xFF for _ in range(MIFARE_1K_bytes_per_key)]


class status(Enum):
    S_NOINIT     = "NO INIT"
    S_OK         = "OK"
    S_NOT_READ   = "NOT READ"
    S_AUTH_ERROR = "AUTH ERROR"
    S_READ_ERROR = "READ ERROR"
    S_WRITE_ERROR= "WRITE ERROR"
    S_KEY_ERROR  = "KEY ERROR"
    S_NO_READERS = "NO READERS"


def parseAccessBits(b6, b7):
    b6 ^= 0xFF #C23│C22│C21│C20│C13│C12│C11│C10 (7-1)
    b7 ^= 0xFF #C33│C32│C31│C30│C23│C22│C21│C20
    #b8 ^= 0xFF #~C13│~C12│~C11│~C10│~C33│~C32│~C31│~C30│ it's checking byte that duplicate info
    blockAcess=bytearray(MIFARE_1K_blocks_per_sector)
    blockAcess[0] = ( (b6       & 0x01)  << 2) | ( (b7       & 0x01) < 1) | ((b7 >> 4) & 0x01)
    blockAcess[1] = (((b6 >> 1) & 0x01)  << 2) | (((b7 >> 1) & 0x01) < 1) | ((b7 >> 5) & 0x01)
    blockAcess[2] = (((b6 >> 2) & 0x01)  << 2) | (((b7 >> 2) & 0x01) < 1) | ((b7 >> 6) & 0x01)
    blockAcess[3] = (((b6 >> 3) & 0x01)  << 2) | (((b7 >> 3) & 0x01) < 1) | ((b7 >> 7) & 0x01)
    return blockAcess
    
bitAccessMap = {
    0b000: "R(A,B) W(A,B) I(A,B) D(A,B)",
    0b001: "R(A,B) W(B,B) I(-) D(-)",
    0b010: "R(A,B) W(B) I(A,B) D(A,B)",
    0b011: "R(B) W(B) I(-) D(-)",
    0b100: "R(A,B) W(B) I(A,B) D(A,B)",
    0b101: "R(B) W(-) I(-,B) D(-,B)",
    0b110: "R(A,B) W(-,B) I(-) D(-)",
    0b111: "R(A,B) W(-) I(-) D(-)"
} 

def bytes2str(b) -> str:
    return "[" + " ".join(f"{ch:02X}" for ch in b) + "]"

#return array of strings, where each string is human representation of block access rights
def accessBitsToStr(accessBytes) -> [str]:
    blockAcess = parseAccessBits(accessBytes[0], accessBytes[1])
    resultStrBlocks = [""  for _ in range(MIFARE_1K_blocks_per_sector)]
    for i in range(MIFARE_1K_blocks_per_sector):
        resultStrBlocks[i] = bitAccessMap.get(blockAcess[i])
    return resultStrBlocks

class keyType(Enum):
    KT_A = "A"
    KT_B = "B"

class key:
    def __init__(self, kType = keyType.KT_A, kData: list[bytes] = MIFARE_1K_default_key):
        self.keyType = kType
        self.keyData = kData

    def toStr(self) -> str:
        return f"{self.keyType.value}:{bytes2str(self.keyData)}"


#full dump data for Mifare 1k card
class dumpMifare_1k:
    #data of each block
    class block:            
        def __init__(self):
            self.data   = bytearray(MIFARE_1K_bytes_per_block)
            self.status = status.S_NOINIT

        def toStr(self, addRespresentation: bool) -> str:
            if self.status == status.S_OK:
                if addRespresentation:
                    byteRepresentation = bytearray(len(self.data))
                    for i,b in enumerate(self.data):
                        byteRepresentation[i] = b if b >= 32 and b <= 126 else 32
                    strRepresentation = "'" + bytes(byteRepresentation).decode(encoding='utf-8', errors='replace') + "'"
                else:
                    strRepresentation = " " * (2 + len(self.data))
                return "  ".join([self.status.value, "["+bytes2str(self.data)+"]", strRepresentation])
            return self.status.value


    #data of block 0 of secor 0
    class head:
        def __init__(self):
            self.UID  = bytearray(4)  #(0-3) first 4 bytes (unique ID of card)
            self.BCC  = 0x00          #(4-4) 4th byte (ecc of UID)
            self.SAK  = bytearray(3)  #(5-7) bytes of block 0 (fabricant data)
            self.SIGN = bytearray(8)  #(7-15)last 8 bytes (sign of manufacturer)

        def read(self, block):
            if block.status == status.S_OK:
                self.UID  = block.data[0:4]
                self.BCC  = block.data[4]
                self.SAK  = block.data[5:8]
                self.SIGN = block.data[8:16]
        
        def toStr(self) -> str:
            return f"UID:{bytes2str(self.UID)} BCC[0x{self.BCC:02X}] SAK:{bytes2str(self.SAK)} SIGN:{bytes2str(self.SIGN)}"

    #data of trailer block (3) of each sector
    class trailer:
        def __init__(self):
            self.keyA       = key(keyType.KT_A) 
            self.keyB       = key(keyType.KT_B) 
            self.accessBits = bytearray(3)
            self.GPB        = 0x00                  #General Purpose Byte
            self.status     = status.S_NOINIT
            
        def processLastBlock(self, data):
            #self.keyA        = data[0:6] #always zero, keyA is unreadable
            self.accessBits   = data[6:9]
            self.GPB          = data[9]
            self.keyB.keyData = data[10:16]
            self.status       = status.S_OK
        
        def toStr(self) -> str:
            if self.status == status.S_OK:
                return f"{self.keyB.toStr()} GPB:{self.GPB:02X} AccessBits:{bytes2str(self.accessBits)}"
            else:
                return "trailer not processed"

    #data of entire sector     
    class sector:
        def __init__(self):
            self.blocks  = [dumpMifare_1k.block() for _ in range(MIFARE_1K_blocks_per_sector)]
            self.trailer = dumpMifare_1k.trailer()
            self.status  = status.S_NOINIT
    
    def __init__(self):
        self.head    = dumpMifare_1k.head()
        self.sectors = [dumpMifare_1k.sector() for _ in range(MIFARE_1K_total_sectors)]
        self.ATR     = bytearray(0)
        self.status  = status.S_NOINIT

############################################################################################################
#dump sector
def printSector(n : int, sector : dumpMifare_1k.sector):
    print(f"sector {n:02d} {sector.status.value}; {sector.trailer.toStr()} -----------------------------------------------")
    accessBitsStr = accessBitsToStr(sector.trailer.accessBits)
    for iBlock, block in enumerate(sector.blocks):
        print (f" {iBlock:02d} {block.toStr(iBlock + 1 < MIFARE_1K_blocks_per_sector)}  access: {accessBitsStr[iBlock]}")


#dump all card info
def printDump(dump, sectors=[0]):
    print(dump.head.toStr())
    for iSector in sectors:
        if iSector >= 0 and iSector < len(dump.sectors):
            printSector(iSector, dump.sectors[iSector])


#print ATR info
def printATR(dump):
    atr = ATR(dump.atr)
    print(f"ATR: T0:{atr.isT0Supported()} T1:{atr.isT1Supported()} T15:{atr.isT15Supported()} GuardTime:{atr.getGuardTime()} Hist btytes {atr.getHistoricalBytes()} ")


