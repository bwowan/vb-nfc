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


def fnPromptSectorIndex_FromTerminal(nSectorCount: int) -> int:
    while True:
        choice = input(f"Sector (0-{nSectorCount - 1}) presss Enter for default 0: ").strip()
        if len(choice) == 0:
            return 0
        else:
            if choice.isdigit():
                value = int(choice)
                if 0 <= value < nSectorCount:
                    return value
        print("Invalid sector number.")

#def isHex(data:)
#=======================================================
class writeDatType(Enum):
    W_DATA = "data" #default
    W_ZERO = "zero"
    W_RAND = "rand"

def dataTypeFromStr(ch: str) -> writeDatType:
    if (len(ch) == 1):
        match ch:
            case '2': return writeDatType.W_ZERO
            case '3': return writeDatType.W_RAND
    return writeDatType.W_DATA

#=======================================================
class writeAddress(Enum):
    A_BLOCK  = "block"   #default
    A_SECTOR = "sector"
    A_ALL    = "all"

def addressFromStr(ch: str) -> writeAddress:
    if (len(ch) == 1):
        match ch:
            case '2': return writeAddress.A_SECTOR
            case '3': return writeAddress.A_ALL
    return writeAddress.A_BLOCK  # default

#=======================================================
class PromptAnswer_ForWrite:
    def __init__(self, nSector = -1, nBlock = -1):
        self.dataType = writeDatType.W_DATA
        self.address  = writeAddress.A_BLOCK
        self.nSector = nSector
        self.nBlock  = nBlock
        self.data    = bytearray(0) 

def fnAskDataToWrite(nSectorCount: int, nBlockCount: int) -> PromptAnswer_ForWrite:
    #match = re.match(r'(\d+)\s+(\d+)(.*)', s)
    while True:
        sys.stdout.write(f"Enter data to write. Format: Sector(0-{nSectorCount-1}) Block(0-{nBlockCount-1}) Data\n")
        sys.stdout.write("Press Enter to exit.\n\n")
        sys.stdout.write("Examples:\n")
        sys.stdout.write("  - Write HEX data into sector 3, block 2:\n    3 2 E7 45 48 03 E9 08 04 00 62 63 64 65 66 67 68 69\n")
        sys.stdout.write("  - Write a string into sector 7, block 1:\n    7 1 hello world\n")
        sys.stdout.write("\nNote: \n")
        sys.stdout.write("- If the data or string is shorter than the block size, it will be padded with zeros.\n")
        sys.stdout.write("- If the data or string exceeds the block size, the application will automatically write to subsequent blocks.\n")
        sys.stdout.write("- Important: The last block of each sector contains keys and access information — it must be written using a separate function.\n")
        sys.stdout.write("- Important: The first block of the first sector stores the card ID — this should only be written once, using a dedicated function.\n")
        inputArray = input().lstrip().split(' ', 2)
        if len(inputArray) == 0:
            return None, None, None
        if len(inputArray) < 3  or not inputArray[0].isdecimal()  or not inputArray[1].isdecimal():
            continue
        nSector = int(inputArray[0])
        if 0 >= nSector  or  nSector >= nSectorCount:
            sys.stdout.write(f"Sector should be 0-{nSectorCount-1}\n")
            continue
        nBlock  = int(inputArray[1])
        if 0 >= nBlock  or  nBlock >= nBlockCount:
            sys.stdout.write(f"Block should be 0-{nBlockCount-2}\n")
            continue
        if nSector == 0  and  nBlock == 0:
            sys.stdout.write("First block of first sector contains card ID information and should be wrote by another function once only!")
            continue
        if nBlock + 1 == nBlockCount:
            sys.stdout.write("last block of each sector contains keys and access information and should be wrote by another function\n")
            continue
        return PromptAnswer_ForWrite(nSector, nBlock, inputArray[2])

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
        sys.stdout.write("\n=============================================================\n")
        for idx, action in enumerate(action_list, start=1):
            sys.stdout.write(f"  {idx} - {action.value}\n")
        choice = input("Select action (press Enter to quit): ").strip().lower()
        if len(choice) == 0:
            return actions.A_QUIT
        else:
            if choice.isdigit():
                pos = int(choice)
                if 1 <= pos <= len(action_list):
                    return action_list[pos - 1]
            sys.stdout.write("Unknown action, try again.\n")


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

#=========================================================================================================
promptStrData = "1) User Data (default)\n2) Zeroes\n3) Random Data\nSelect data type (1-3):"
promptStrAddr = "1) Block (default)    \n2) Sector\n3) Entire card\nSelect data address (1-3):"

def fnAskWrite(nSectorCount: int, nBlockCount: int) -> (bool, PromptAnswer_ForWrite):
    print("=== NFC WRITE MENU ===")    
    answer = PromptAnswer_ForWrite()
    answer.dataType = dataTypeFromStr(getUserInput(promptStrData, ['', '1', '2', '3']))    
    if answer.dataType == writeDatType.W_DATA: 
        answer.address = writeAddress.A_BLOCK
        print("Automatic selection: write block in sector\n")
    else:
        answer.address = addressFromStr(getUserInput(promptStrAddr, ['', '1', '2', '3']))
    
    # Third level menu
    isOk = False
    if answer.address == writeAddress.A_ALL:
        isOk = 'Y' == getUserInput("Writing to entire card... (Yes/No): ", ['Y', 'YES', 'N', 'NO'])[0]
    else:
        isOk, answer.nSector = askSectorNumber_FromTerminal(nSectorCount)
        if isOk:
            match answer.address:
                case writeAddress.A_BLOCK:
                    isOk, answer.nBlock = askBlockNumber_FromTerminal(answer.nSector, nBlockCount)
                    if isOk:
                        print(f"Selected: Block {answer.nBlock} in Sector {answer.nSector}")
                case writeAddress.A_SECTOR:
                    isOk = 'Y' == getUserInput("Writing to entire sector {answer.nSector}... (Yes/No): ", ['Y', 'YES', 'N', 'NO'])[0]

    return isOk, answer

if __name__ == "__main__":
    print(fnAskWrite(16, 4))