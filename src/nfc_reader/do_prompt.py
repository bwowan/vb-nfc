from enum import Enum
import sys
import os
import select
import threading
#import card_data

class actions(Enum):
    A_READ           = "read card"
    A_READ_KEY       = "read key"
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


"""

def fnInputString_FromTerminal_WithCancellation(prompt: str, cancelEvent: threading.Event) -> str:
    """
    Non-blocking input with cancellation support, returns empty string if cancelled.
    Note: On Windows, select() doesn't work with stdin, so this will fall back to blocking input.
          On Linux/Unix, select() allows  periodic cancellation checks.
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    
    # Use select for non-blocking read (Linux/Unix only)
    readDone,resultStr = False,""
    breakInput,breakStr = False, ""
    if sys.stdin.isatty():
        try:
            while not readDone  and  not cancelEvent.is_set():
                ready, _, _ = select.select([sys.stdin], [], [], 0.1) # Check if input is available (timeout 0.1 seconds)
                if ready:
                    resultStr = sys.stdin.readline().rstrip('\n')
                    readDone = True
        except KeyboardInterrupt: # user interrupted input (Ctrl+C)
            breakInput, breakStr = True, "Program interrupted. Exiting..."
        except EOFError:
            breakInput, breakStr = True, "Input error. Exiting..."
        except (OSError, ValueError, AttributeError): # select doesn't work (Windows or other issues)
            sys.stdout.write("\n")
            sys.stdout.flush()
           
    if not breakInput:
        if not readDone  and  not cancelEvent.is_set(): #if problem with select, use blocking input
            try:
                resultStr = input()
            except KeyboardInterrupt:
                breakInput, breakStr = True, "Program interrupted. Exiting..."
            except EOFError:
                breakInput, breakStr = True, "Input error. Exiting..."

    if breakInput:
        print(f"\n{breakStr}\n")
        sys.exit(0)
    else:
        return resultStr


def fnPromptUserAction_FromTerminal(cancelEvent: threading.Event) -> actions:
    #Prompt user for action with optional cancellation support.
    #If cancelEvent is set, will interrupt input and return A_QUIT.
    #Returns: Selected action or A_QUIT if cancelled.
    action_list = list(actions)
    while True:
        if cancelEvent.is_set():
            return actions.A_READ
        else:
            print("\n=============================================================")
            for idx, action in enumerate(action_list, start=1):
                print(f"  {idx} - {action.value}")            
            choice = fnInputString_FromTerminal_WithCancellation("Select action (press Enter to quit): ", cancelEvent).strip()
            if cancelEvent.is_set():
                return actions.A_READ
            else:
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

def getUserInput(prompt: str, checkRange, cancelEvent: threading.Event) -> str:
    while True:
        inputStr = fnInputString_FromTerminal_WithCancellation(prompt, cancelEvent).strip().upper()
        if len(inputStr) == 0  or  inputStr in checkRange: #break or correct input
            return inputStr
        else:
            print(f"Invalid input. Please input:{checkRange}")


def askNumber_FromTerminal(nMin: int, nMax: int, sPrompt: str, cancelEvent: threading.Event) -> (bool, int):
    numbers = [str(i) for i in range(nMin, nMax + 1)]
    inputStr = getUserInput(sPrompt + f"({nMin}-{nMax}): ", numbers, cancelEvent).strip()
    if len(inputStr) != 0  and  inputStr.isdigit():
        return True, int(inputStr)
    return False, -1

def askSectorNumber_FromTerminal(nSectorCount: int, cancelEvent: threading.Event) -> (bool, int):
    return askNumber_FromTerminal(0, nSectorCount - 1, "Enter sector number", cancelEvent)

def askBlockNumber_FromTerminal(sector: int, nBlockCount: int, cancelEvent: threading.Event) ->  (bool, int):
    return askNumber_FromTerminal(1 if sector==0 else 0, nBlockCount - 2, "Enter block number", cancelEvent)

def askConfirmWrite_FromTerminal(sPrompt: str, cancelEvent: threading.Event) -> bool:
    inputStr = getUserInput(f"{sPrompt} (Yes/No): ", ['Y', 'YES', 'N', 'NO'], cancelEvent).strip().upper()
    return len(inputStr) != 0  and  inputStr[0] == 'Y'

def askTextData_FromTerminal(nBlockSize: int, cancelEvent: threading.Event) -> str:
    dataText = fnInputString_FromTerminal_WithCancellation("Enter text string (e.g. hello world): ",
                                                           cancelEvent)
    if len(dataText) == 0:
        print("Text string cannot be empty.")
        return bytearray(0)
    else:
        return (dataText + ' ' * (nBlockSize - len(dataText) % nBlockSize)).encode('utf-8')


def askHexData_FromTerminal(nBlockSize: int, cancelEvent: threading.Event) -> bytearray:
    readDone,dataBinary = False,bytearray(0)
    while not readDone:
        dataText = fnInputString_FromTerminal_WithCancellation("Enter hexadecimal data (e.g., E7 45 00 98 03 FF D1 C6...): ", 
                                                               cancelEvent).strip().upper()
        if len(dataText) == 0:
            print("Hexadecimal data can't be empty.")
            readDone = True
        else:
            try:
                dataBinary = bytearray.fromhex(dataText)
                readDone = True
            except ValueError:
                print("Invalid hexadecimal format. Use only 0-9, A-F characters. Try again or press Ctrl+C to cancel.")
    
    if len(dataBinary) > 0:
        padding = nBlockSize - len(dataBinary) % nBlockSize
        return dataBinary if padding == 0 else dataBinary + bytearray(padding)
    return dataBinary

#return key type: "A" or "B",  list[bytes] - 6 bytes of key data
def askKey_FromTerminal(keyLength: int, cancelEvent: threading.Event) -> (bool, str, list[bytes]):
    # Ask for key type (A or B, default: B)
    keyDataBytes = bytearray(0)
    keyTypeStr = getUserInput("Enter key type (A or B): ", ['A','B'], cancelEvent)
    if len(keyTypeStr) == 1:
        n = 0
        while len(keyDataBytes) != keyLength  and  not cancelEvent.is_set():
            n += 1
            if n > 4:
                return False, "", []
            keyDataStr = fnInputString_FromTerminal_WithCancellation(
                f"Enter key ({keyLength} hex bytes (e.g. A3 95 E7 45 00 98), press Enter for default): {'FF ' * keyLength}",
                cancelEvent
            ).strip().upper()
            if not cancelEvent.is_set():
                if len(keyDataStr) == 0:
                    keyDataBytes = bytearray([0xFF] * keyLength)
                else:
                    try:
                        keyDataBytes = bytearray.fromhex(keyDataStr.replace("_", " ").replace(",", " "))
                        if len(keyDataBytes) != keyLength:
                            print(f"Invalid key length. Key must be {keyLength} hex bytes.")
                    except ValueError:
                        print("Invalid hexadecimal format. Use only 0-9, A-F characters. Try again or press Ctrl+C to cancel.")

    return len(keyDataBytes) == keyLength, keyTypeStr, keyDataBytes


#=========================================================================================================
def __countDataSize(nSectorCount: int, nBlockCount: int, nBlockSize: int, answer: PromptAnswer_ForWrite) -> int:
    match answer.address:
        case writeAddress.A_BLOCK:
            return nBlockSize
        case writeAddress.A_SECTOR:
            #first sector contains card ID and access information
            return nBlockSize *  (nBlockCount - 1 if answer.nSector != 0 else 2)
        case writeAddress.A_ALL:
            #-1 because first block of sector is special and last block of each sector is access information
            return nBlockSize * ((nBlockCount - 1)* nSectorCount - 1)
    return 0    #should not happen

promptStrData = "--- Select data type ---   \n1) String (default)\n2) User Data\n3) Zeros\n4) Random\n (1-4)?:"
promptStrAddr = "--- Select data address ---\n1) Block (default)\n2) Sector\n3) Entire card\n (1-3)?:"

def fnAskWrite(nSectorCount: int, nBlockCount: int, nBlockSize: int, cancelEvent: threading.Event) -> (bool, PromptAnswer_ForWrite):
    print("\n---------------------------------------------------------\nNotes:")
    print("- If the data or string is shorter than the block size, it will be padded with zeros.")
    print("- If the data or string exceeds the block size, the application will automatically write to subsequent blocks.")
    print("- Important: The last block of each sector contains keys and access information — it must be written using a separate function.")
    print("- Important: The first block of the first sector stores the card ID — this should only be written once, using a dedicated function.")

    answer = PromptAnswer_ForWrite()
    answer.dataType = dataTypeFromStr(getUserInput(promptStrData, ['', '1', '2', '3', '4'], cancelEvent))
    print(f"Selected data type: {answer.dataType.value}")
    if answer.dataType == writeDatType.W_DATA  or  answer.dataType == writeDatType.W_STR:
        answer.address = writeAddress.A_BLOCK
    else:
        answer.address = addressFromStr(getUserInput(promptStrAddr, ['', '1', '2', '3'], cancelEvent))
    
    # Third level menu
    isOk = False
    if answer.address == writeAddress.A_ALL:
        isOk = askConfirmWrite_FromTerminal("Writing to entire card...", cancelEvent)
    else:
        isOk, answer.nSector = askSectorNumber_FromTerminal(nSectorCount, cancelEvent)
        if isOk:
            match answer.address:
                case writeAddress.A_BLOCK:
                    isOk, answer.nBlock = askBlockNumber_FromTerminal(answer.nSector, nBlockCount, cancelEvent)
                    isOk and print(f"Selected: Block {answer.nBlock} in Sector {answer.nSector}")
                case writeAddress.A_SECTOR:
                    isOk = askConfirmWrite_FromTerminal(f"Writing to entire sector {answer.nSector}...", cancelEvent)
                    if isOk:
                        answer.nBlock = 0 if answer.nSector != 0 else 1 #first block of sector is special
    
    if isOk:
        match answer.dataType:
            case writeDatType.W_STR: # Request data for string type
                answer.data = askTextData_FromTerminal(nBlockSize, cancelEvent)
            case writeDatType.W_DATA: # Request data for user data type
                answer.data = askHexData_FromTerminal(nBlockSize, cancelEvent)
            case writeDatType.W_ZERO: # Generate data for zeros type
                answer.data = bytearray(__countDataSize(nSectorCount, nBlockCount, nBlockSize, answer))
            case writeDatType.W_RAND: # Generate data for random type
                answer.data = os.urandom(__countDataSize(nSectorCount, nBlockCount, nBlockSize, answer))
    if len(answer.data) > 0:
        return True, answer
    return False, None

if __name__ == "__main__":
    print(askKey_FromTerminal(6, threading.Event()))
    isOk, answer = fnAskWrite(16, 4, 16, threading.Event())
    if isOk:
        print(f"Selected: {answer.dataType.value} --> {answer.address.value} [{answer.nSector}:{answer.nBlock}]")
        if answer.dataType == writeDatType.W_STR  or  answer.dataType == writeDatType.W_DATA: 
            print(f"-->{answer.data.decode('utf-8')}\n")
    else:
        print("No data selected")