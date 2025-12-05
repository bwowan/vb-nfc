from enum import Enum
import sys
import os
#import card_data

class actions(Enum):
    A_READ           = "read card"
    A_PRINT_ALL      = "print all data"
    A_PRINT_SECTOR   = "print single sector"
    A_WRITE          = "write block interactively"
    A_QUIT           = "quit"

class writeDatType(Enum):
    W_STR  = "string"  #default
    W_DATA = "data" 
    W_ZERO = "zeros"
    W_RAND = "random"

class writeAddress(Enum):
    A_BLOCK  = "block"   #default
    A_SECTOR = "sector"
    A_ALL    = "entire card"

def dataTypeFromStr(ch: str) -> writeDatType:
    if (len(ch) == 1):
        match ch:
            case '1': return writeDatType.W_DATA
            case '3': return writeDatType.W_ZERO
            case '4': return writeDatType.W_RAND
    return writeDatType.W_STR

def addressFromStr(ch: str) -> writeAddress:
    if (len(ch) == 1):
        match ch:
            case '2': return writeAddress.A_SECTOR
            case '3': return writeAddress.A_ALL
    return writeAddress.A_BLOCK  # default


#=======================================================
class PromptAnswer_ForWrite:
    def __init__(self, nSector = -1, nBlock = -1):
        self.dataType   = writeDatType.W_DATA
        self.address    = writeAddress.A_BLOCK
        self.nSector    = nSector
        self.nBlock     = nBlock
        self.data       = bytearray(0)


"""
def fnPromptBlockIndex_FromTerminal():
    while True:
        choice = input(f"Block (0-{card_data.MIFARE_1K_blocks_per_sector - 1}): ").strip()
        if choice.isdigit():
            value = int(choice)
            if 0 <= value < card_data.MIFARE_1K_blocks_per_sector:
                return value
            else:
                print(f"Invalid block number. Must be 0-{card_data.MIFARE_1K_blocks_per_sector - 1}.")

def fnPromptKey_FromTerminal():
    while True:
        key  = input("Key (12 hex digits, for default key:FF FF FF FF FF FF just press Enter: ")
        key  = key.replace(" ", "").replace("_", "").upper()
        if len(key) != card_data.MIFARE_1K_bytes_per_key * 2:
            print(f"Key must be {card_data.MIFARE_1K_bytes_per_key * 2} hex digits, ({card_data.MIFARE_1K_bytes_per_key} bytes, eg:0A 01 00 F5 10 ED).")
        else:
            try:
                return [int(key[i:i+2], 16) for i in range(0, len(key), 2)]
            except ValueError:
                print("Invalid hex format. Use only 0-9, A-F characters.")


def fnPromptBlockData_FromTerminal():
    while True:
        data_str = input(f"Block data (32 hex digits), default is: {'00 ' * card_data.MIFARE_1K_bytes_per_block}: ")
        data_str = data_str.replace(" ", "").replace("_", "").upper()
        if len(data_str) != card_data.MIFARE_1K_bytes_per_block * 2:
            print(f"Data must be {card_data.MIFARE_1K_bytes_per_block * 2} hex digits ({card_data.MIFARE_1K_bytes_per_block} bytes).")
        else:
            try:
                return [int(data_str[i:i+2], 16) for i in range(0, len(data_str), 2)]
            except ValueError:
                print("Invalid hex format. Use only 0-9, A-F characters.")
"""

def fnPromptUserAction_FromTerminal():
    action_list = list(actions)
    while True:
        print("\n=============================================================")
        for idx, action in enumerate(action_list, start=1):
            print(f"  {idx} - {action.value}")
        choice = input("Select action (press Enter to quit): ").strip().lower()
        if len(choice) == 0:
            return actions.A_QUIT
        else:
            if choice.isdigit():
                pos = int(choice)
                if 1 <= pos <= len(action_list):
                    return action_list[pos - 1]
            print("Unknown action, try again.")


#============================================================================================================
def clearScreen():
    os.system('cls' if os.name == 'nt' else 'clear')

def getUserInput(prompt: str, checkRange):
    while True:
        try:
            userInput = input(prompt).strip().upper()
            if userInput in checkRange:
                return userInput
            else:
                print(f"Invalid input. Please input:{checkRange}")
        except KeyboardInterrupt:
            print("\n\nProgram interrupted. Exiting...")
            sys.exit(0)
        except EOFError:
            print("\n\nInput error. Exiting...")
            sys.exit(0)

def askNumber_FromTerminal(nMin: int, nMax: int, sPrompt: str) -> (bool, int):
    numbers = [str(i) for i in range(nMin, nMax + 1)]
    sInput = getUserInput(sPrompt + f"({nMin}-{nMax}): ", numbers).strip()
    if len(sInput) != 0  and  sInput.isdigit():
        return True, int(sInput)
    return False, -1

def askSectorNumber_FromTerminal(nSectorCount: int) -> (bool, int):
    return askNumber_FromTerminal(0, nSectorCount - 1, "Enter sector number")

def askBlockNumber_FromTerminal(sector: int, nBlockCount: int) -> (bool, int):
    return askNumber_FromTerminal(1 if sector==0 else 0, nBlockCount - 2, "Enter block number")

def askConfirmWrite_FromTerminal(sPrompt: str) -> bool:
    return 'Y' == getUserInput(f"{sPrompt} (Yes/No): ", ['Y', 'YES', 'N', 'NO'])[0]

def askTextData_FromTerminal(nBlockSize: int) -> str:
    dataText = ""
    while len(dataText) == 0:
        try:
            dataText = input("Enter text string (e.g. hello world): ")
            if len(dataText) == 0:
                print("Text string cannot be empty. Try again or press Ctrl+C to cancel.")
        except KeyboardInterrupt:
            break

    if len(dataText) > 0:
        return (dataText + ' ' * (nBlockSize - len(dataText) % nBlockSize)).encode('utf-8')
    return bytearray(0)


def askHexData_FromTerminal(nBlockSize: int) -> bytearray:
    dataBinary = bytearray(0)
    while len(dataBinary) == 0:
        try:
            dataText = input("Enter hexadecimal data (e.g., E7 45 00 98 03 FF D1 C6...): ").upper()
        except KeyboardInterrupt:
            break
        if len(dataText) == 0:
            print("Hexadecimal data can't be empty. Try again or press Ctrl+C to cancel.")
        else:
            try:
                dataBinary = bytearray.fromhex(dataText)
                break
            except ValueError:
                print("Invalid hexadecimal format. Use only 0-9, A-F characters. Try again or press Ctrl+C to cancel.")
    
    if len(dataBinary) > 0:
        padding = nBlockSize - len(dataBinary) % nBlockSize
        return dataBinary if padding == 0 else dataBinary + bytearray(padding)
    return bytearray(0)


#=========================================================================================================
promptStrData = "--- Select data type ---   \n1) String (default)\n2) User Data\n3) Zeros\n4) Random\n (1-4)?:"
promptStrAddr = "--- Select data address ---\n1) Block (default)\n2) Sector\n3) Entire card\n (1-3)?:"

def fnAskWrite(nSectorCount: int, nBlockCount: int, nBlockSize: int) -> (bool, PromptAnswer_ForWrite):
    print("\n---------------------------------------------------------\nNotes:")
    print("- If the data or string is shorter than the block size, it will be padded with zeros.")
    print("- If the data or string exceeds the block size, the application will automatically write to subsequent blocks.")
    print("- Important: The last block of each sector contains keys and access information — it must be written using a separate function.")
    print("- Important: The first block of the first sector stores the card ID — this should only be written once, using a dedicated function.")

    answer = PromptAnswer_ForWrite()
    answer.dataType = dataTypeFromStr(getUserInput(promptStrData, ['', '1', '2', '3', '4']))
    print(f"Selected data type: {answer.dataType.value}")
    if answer.dataType == writeDatType.W_DATA  or  answer.dataType == writeDatType.W_STR:
        answer.address = writeAddress.A_BLOCK
    else:
        answer.address = addressFromStr(getUserInput(promptStrAddr, ['', '1', '2', '3']))
    
    # Third level menu
    isOk = False
    if answer.address == writeAddress.A_ALL:
        isOk = askConfirmWrite_FromTerminal("Writing to entire card...")
    else:
        isOk, answer.nSector = askSectorNumber_FromTerminal(nSectorCount)
        if isOk:
            match answer.address:
                case writeAddress.A_BLOCK:
                    isOk, answer.nBlock = askBlockNumber_FromTerminal(answer.nSector, nBlockCount)
                    isOk and print(f"Selected: Block {answer.nBlock} in Sector {answer.nSector}")
                case writeAddress.A_SECTOR:
                    isOk = askConfirmWrite_FromTerminal(f"Writing to entire sector {answer.nSector}...")
    
    if isOk:
        match answer.dataType:
            case writeDatType.W_STR: # Request data for string type
                answer.data = askTextData_FromTerminal(nBlockSize)
            case writeDatType.W_DATA: # Request data for user data type
                answer.data = askHexData_FromTerminal(nBlockSize)
            case writeDatType.W_ZERO: # Generate data for zeros type
                match answer.address:
                    case writeAddress.A_BLOCK:
                        answer.data = bytearray(nBlockSize)
                    case writeAddress.A_SECTOR:
                        answer.data = bytearray(nBlockSize * (nBlockCount - 1))
                    case writeAddress.A_ALL:
                        answer.data = bytearray(nBlockSize * (nBlockCount - 1) * nSectorCount)
            case writeDatType.W_RAND: # Generate data for random type
                match answer.address:
                    case writeAddress.A_BLOCK:
                        answer.data = os.urandom(nBlockSize)
                    case writeAddress.A_SECTOR:
                        answer.data = os.urandom(nBlockSize * (nBlockCount - 1))
                    case writeAddress.A_ALL:
                        answer.data = os.urandom(nBlockSize * (nBlockCount - 1)* nSectorCount)
    if len(answer.data) > 0:
        return True, answer
    return False, None

if __name__ == "__main__":
    isOk, answer = fnAskWrite(16, 4, 16)
    if isOk:
        print(f"Selected: {answer.dataType.value} --> {answer.address.value} [{answer.nSector}:{answer.nBlock}]\n")
        if answer.dataType == writeDatType.W_STR  or  answer.dataType == writeDatType.W_DATA: 
            print(f"-->{answer.data.decode('utf-8')}\n")
    else:
        print("No data selected")