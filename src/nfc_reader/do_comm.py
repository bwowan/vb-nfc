import sys
from smartcard.CardConnection import CardConnection



"""
def _normalize_hex(data: str) -> List[int]:
    sanitized = data.replace(" ", "").replace("_", "").lower()
    if len(sanitized) != card_data.MIFARE_1K_bytes_per_block * 2:
        raise WritePlanError(f"Expected {card_data.MIFARE_1K_bytes_per_block} bytes, got {len(sanitized) // 2}")
    try:
        return [int(sanitized[i : i + 2], 16) for i in range(0, len(sanitized), 2)]
    except ValueError as exc:
        raise WritePlanError(f"Invalid hex data: {data}") from exc
"""


#send request to card
def fnDoTransmit(connection, Key):
    try:
        response, sw1, sw2 = connection.transmit(Key)
        if (sw1 == 0x90) and (sw2 == 0x00):
            return True, response
    except Exception as e:
        print(f"transmit error: {e}")
    return False


def fnLoadKey(connection: CardConnection, key: list[bytes]) -> bool:
    if fnDoTransmit(connection, [0xFF, 0x82, 0x00, 0x00, len(key)] + list(key)):
        return True
    else:
        sys.stdout.write(f"fail to load key: {key}")
        return False

def fnSelectBlock(connection: CardConnection, nBlock: int) -> bool:
    if fnDoTransmit(connection, [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, nBlock, 0x60, 0x00]):
        return True
    else:
        sys.stdout.write(f"Authentication failed for block: {nBlock//4}:{nBlock%4}")
        return False

def fnWriteBlock(connection: CardConnection, nBlock: int, data: list[bytes]) -> bool:
    if fnDoTransmit(connection, [0xFF, 0xD6, 0x00, nBlock, len(data)] + data):
        return True
    else:
        sys.stdout.write(f"fail to write block: {nBlock//4}:{nBlock%4}")
        return False

def fnReadBlock(connection: CardConnection, nBlock: int, count: int = 0x10):
    Result, responce = fnDoTransmit(connection, [0xFF, 0xB0, 0x00, nBlock, count])
    if not Result:
        sys.stdout.write(f"failed to read block: {nBlock//4}:{nBlock%4}")
    return Result, responce
