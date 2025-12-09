import sys
import time 
import queue
import threading
import smartcard.System
from enum                      import Enum
from smartcard.CardRequest     import CardRequest
from smartcard.CardMonitoring  import CardMonitor, CardObserver
from smartcard.CardConnection  import CardConnection

import card_data
import do_prompt
import do_wr


TIME_TO_WAIT_CARD = 12

readers = []

class actResponce(Enum):
    A_RESPONCE_OK       = "done"
    A_RESPONCE_FAIL     = "fail"

    @staticmethod
    def fromBool(isOk:bool) -> "actResponce":
        return actResponce.A_RESPONCE_OK if isOk else actResponce.A_RESPONCE_FAIL


#Manages user input thread with cancellation support (if card removed, input thread will be cancelled).
#Prevents resource leaks by tracking and cleaning up threads.
class BackgroundInputProcessor:
    def __init__(self) -> None:
        self.inputThread = None 
        self.resultQueue = queue.Queue(maxsize=1)
        self.cancelEvent = threading.Event()
        self.lock = threading.Lock()  
        
    #Start input thread, cancelling previous one if exists.
    def start(self) -> None:
        with self.lock:
            # Cancel previous input if still running
            if self.inputThread is not None  and  self.inputThread.is_alive():
                self.cancelEvent.set()
                self.inputThread.join()
            
            # Reset event and start new thread
            self.cancelEvent.clear()
            self.inputThread = threading.Thread(target=self.process, daemon=True)
            self.inputThread.start()
    
    #thread function for input processing.
    def process(self) -> None:
        try:
            action = do_prompt.fnPromptUserAction_FromTerminal(self.cancelEvent)
            self.resultQueue.put(action)
        except Exception as e:
            self.resultQueue.put(do_prompt.actions.A_QUIT)

    
    #Cancel current input operation.
    def cancel(self):
        with self.lock:
            self.cancelEvent.set()

    # Get result from input thread.
    def getInput(self) -> do_prompt.actions:
        self.resultQueue.join()
        result = self.resultQueue.get()
        self.resultQueue.task_done()
        return result


   #stop and cleanup input thread
    def cleanup(self):
        with self.lock:
            self.cancelEvent.set()
            if self.inputThread is not None  and  self.inputThread.is_alive():
                self.inputThread.join()
            self.inputThread = None

#=================================
class CardProcessor():
    class processData():
        def __init__(self) -> None:
            self.sectorIndex = -1
            self.blockIndex  = -1
            self.key         = card_data.MIFARE_1K_default_key
            self.blockData   = bytearray(card_data.MIFARE_1K_bytes_per_block)

    class LocalCardObeserver(CardObserver):
        def __init__(self, insertEvent: threading.Event) -> None:
            super().__init__()
            self.insertEvent    = insertEvent
            self.monitor        = CardMonitor()
            self.ATR            = bytearray(0)
            self.inputProcessor = BackgroundInputProcessor()
            self.monitor.addObserver(self)

        #callback function for smartcard library (background thread)
        def update(self, observable, handlers) -> None:
            inserted, removed = handlers
            if len(inserted) != 0: #we have a card inserted
                sys.stdout.write(f"\rInserted: {card_data.bytes2str(inserted[0].atr)}\n")
                self.insertEvent.set()
            if len(removed) != 0:
                self.insertEvent.clear()
                sys.stdout.write(f"\rRemoved: {card_data.bytes2str(removed[0].atr)}\n")
                self.inputProcessor.cancel()


        def waitForConnection(self):
            self.insertEvent.wait(timeout=1)
            if self.insertEvent.is_set():
                try:
                    cardRequest    = CardRequest(timeout=1)
                    cardService    = cardRequest.waitforcard()
                    cardConnection = cardService.connection
                    cardConnection.connect(mode=smartcard.scard.SCARD_SHARE_EXCLUSIVE, disposition=smartcard.scard.SCARD_UNPOWER_CARD)
                    self.ATR = cardConnection.getATR()
                    return True, cardRequest, cardService, cardConnection
                except Exception as e:
                    sys.stdout.write(f"\nConnection error {e}\n")
            else:
                sys.stdout.write("\rconnection timeout            ")
            return False, None, None, None


    def executeCommunication(self, operation: callable):  
        isOkConnection, cardRequest, cardService, cardConnection = self.observer.waitForConnection()
        isOkResult = isOkConnection and operation(cardConnection)
        isOkConnection and cardConnection.disconnect()
        self.responceQueue.put(actResponce.fromBool(isOkResult))


    #main service thread loop
    def process(self) -> None: #loop of main thread
        try:
            doContinue = True
            while doContinue:
                self.responceQueue.join()
                msg = self.messageQueue.get()
                match msg:
                    case do_prompt.actions.A_QUIT:
                        doContinue = False
                        self.observer.monitor.deleteObserver(self.observer)
                        self.responceQueue.put(actResponce.A_RESPONCE_OK)

                    case do_prompt.actions.A_READ:
                        self.executeCommunication(lambda conn: do_wr.fnRead(self.dump, conn, self.key))

                    case do_prompt.actions.A_WRITE:
                        self.executeCommunication(lambda conn: do_wr.fnWrite(self.writeData, conn, self.key))

                self.messageQueue.task_done()
        except Exception as e:
            print(f"{e}")
            
            
    def __init__(self) -> None:
        self.messageQueue     = queue.Queue(maxsize=2)
        self.responceQueue    = queue.Queue(maxsize=2)
        self.dump             = card_data.dumpMifare_1k()
        self.dataToProcess    = CardProcessor.processData()
        self.cardInsertedEvent= threading.Event()
        self.selfTask         = threading.Thread(target=self.process, daemon=True)
        self.writeData        = do_prompt.PromptAnswer_ForWrite()
        self.key              = card_data.key(card_data.keyType.KT_B)
        self.observer         = CardProcessor.LocalCardObeserver(self.cardInsertedEvent)

#waiting while ervice thread process it's queue
def fnWaitForResponce(queueResponce: queue.Queue) -> bool:
    Result = queueResponce.get(block=True) == actResponce.A_RESPONCE_OK
    queueResponce.task_done()
    return Result


def printWaiting(e: threading.Event, s=" "):
    if not e.is_set():
        sys.stdout.write(f"\rwaiting or card {s}")
        time.sleep(0.4)

def WaitForCard(e: threading.Event):
    nWaitStr = 0
    waitStr = ["( )", "(.)", "(-)", "(+)", "(-)", "(.)"]
    sys.stdout.write("\n")
    while not e.is_set():
        time.sleep(0.3)
        if nWaitStr >= len(waitStr)  or  nWaitStr < 0:
            nWaitStr = 0
        if not e.is_set():
            sys.stdout.write(f"\rwaiting or card {waitStr[nWaitStr]}")
        nWaitStr += 1


###################################################
if __name__ == "__main__":
    readers = smartcard.System.readers()
    if not readers:
        print("no readers")
    else:
        print(readers[0])
        # Create input manager for interruptible user input
        mainCardProcessor = CardProcessor()
        mainCardProcessor.selfTask.start()
        action = do_prompt.actions.A_READ

        try:
            while mainCardProcessor.selfTask.is_alive():
                # Skip action processing if action is None (input was cancelled in previous iteration)
                if action is not None:
                    if action == do_prompt.actions.A_READ  or action == do_prompt.actions.A_WRITE:
                        WaitForCard(mainCardProcessor.cardInsertedEvent)

                    match action:
                        case do_prompt.actions.A_READ:
                            mainCardProcessor.messageQueue.put(do_prompt.actions.A_READ)
                            if fnWaitForResponce(mainCardProcessor.responceQueue):
                                card_data.printSector(0, mainCardProcessor.dump.sectors[0])

                        case do_prompt.actions.A_PRINT_SECTOR:
                            isOk, nSector = do_prompt.askSectorNumber_FromTerminal(card_data.MIFARE_1K_total_sectors)
                            isOk and card_data.printSector(nSector, mainCardProcessor.dump.sectors[nSector])

                        case do_prompt.actions.A_WRITE:
                            isOk, mainCardProcessor.writeData = do_prompt.fnAskWrite(card_data.MIFARE_1K_total_sectors,
                                                                                     card_data.MIFARE_1K_blocks_per_sector,
                                                                                     card_data.MIFARE_1K_bytes_per_block)
                            if isOk:
                                mainCardProcessor.messageQueue.put(do_prompt.actions.A_WRITE)
                                fnWaitForResponce(mainCardProcessor.responceQueue)

                        case do_prompt.actions.A_PRINT_ALL:
                            all_sectors = list(range(card_data.MIFARE_1K_total_sectors))
                            card_data.printDump(mainCardProcessor.dump, sectors=all_sectors)

                        case do_prompt.actions.A_QUIT:
                            mainCardProcessor.messageQueue.put(do_prompt.actions.A_QUIT)
                            if fnWaitForResponce(mainCardProcessor.responceQueue):
                                break
                
                # Start input in separate thread and wait for result
                mainCardProcessor.observer.inputProcessor.start()
                action = mainCardProcessor.observer.inputProcessor.getInput()  # Wait until result or cancellation
        finally:
            # Cleanup: cancel input and wait for thread to finish
            mainCardProcessor.observer.inputProcessor.cleanup()

        sys.stdout.write("\rgood by\n\n")

