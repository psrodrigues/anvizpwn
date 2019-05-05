import socket
import anvizCRC

# GLOBAL VARIABLES

STX = b"\xA5"  # Preamble

# REQUESTS
CMD_GET_INFO = b'\x30'  # GET INFO
CMD_SET_INFO = b'\x31'  # SET INFO
CMD_GET_INFO_EXTENDED = b'\x32'  # GET INFO Extended
CMD_SET_INFO_EXTENDED = b'\x33'  # SET INFO
CMD_GET_DATE = b'\x38'  # GET DATE
CMD_SET_DATE = b'\x39'  # SET DATE
CMD_GET_NETWORK = b'\x3A'  # GET TCP/IP Configurations
CMD_SET_NETWORK = b'\x3B'  # SET TCP/IP Configurations
CMD_GET_RECORDS = b'\x3C'  # GET RECORDS
CMD_DOWNLOAD_RECORDS = b'\x40'  # DOWNLOAD RECORDS
CMD_UPLOAD_RECORDS = b'\x41'  # UPLOAD RECORDS
CMD_DOWNLOAD_INFO = b'\x42'  # DOWNLOAD STAFF INFO
CMD_DOWNLOAD_FINGERPRINT = b'\x44'  # DOWNLOAD USER FINGERPRINT
CMD_UPLOAD_FINGERPRINT = b'\x45'  # UPLOAD USER FINGERPRINT
CMD_GET_SN = b'\x46'  # GET DEVICE SN
CMD_SET_SN = b'\x47'  # SET DEVICE SN
CMD_GET_TYPECODE = b'\x48'  # GET DEVICE TYPE CODE
CMD_SET_TYPECODE = b'\x49'  # SET DEVICE TYPE CODE
CMD_GET_FACTORYINFOCODE = b'\x4A'  # GET DEVICE TYPE CODE
CMD_SET_FACTORYINFOCODE = b'\x4B'  # SET DEVICE TYPE CODE
CMD_DEL_USERDATA = b'\x4C'  # DELETE USER DATA
CMD_INIT_USERDATA = b'\x4D'  # Init User Data
CMD_DEL_RECORDS = b'\x4E'  # Delete Records
CMD_INIT_SYSTEM = b'\x4F'  # Init SYSTEM
CMD_GET_TIMEZONE = b'\x50'  # GET TIMEZONE
CMD_SET_TIMEZONE = b'\x51'  # SET TIMEZONE
CMD_GET_GROUPINFO = b'\x52'  # GET GROUP INFO
CMD_SET_GROUPINFO = b'\x53'  # SET GROUP INFO
CMD_GET_BELLINFO = b'\x54'  # GET Scheduale Bell info
CMD_SET_RINGINFO = b'\x55'  # SET Ring Info
CMD_GET_MESSAGE = b'\x56'  # GET Messages
CMD_SET_MESSAGE = b'\x57'  # SET messages
CMD_GET_MESSAGES_HEADERS = b'\x58'  # GET Messages subjects
CMD_DEL_MESSAGE = b'\x59'  # DELETE MESSAGES
CMD_GET_STATEMESSASE = b'\x5A'  # GET T&A STATE MESSAGES ENTER;EXIT;BREAK
CMD_SET_STATEMESSASE = b'\x5B'  # SET T&A STATE MESSAGES
CMD_ENROLL_FP_ONLINE = b'\x5C'  # ENROLL FINGERPRINT, USE DEVICE TO SCAN
CMD_GET_CAPACITY = b'\x5A'  # GET CAPACITY
CMD_OPENDOOR = b'\x5E'  # Open Door
CMD_SET_RECORD = b'\x5F'  # Adds record
CMD_GET_CUSTOMSTATETABLE = b'\x70'  # GET T&A STATE Table
CMD_SET_CUSTOMSTATETABLE = b'\x71'  # SET T&A STATE Table
CMD_DOWNLOAD_USERS = b'\x72'  # DOWNLOAD Users
CMD_UPLOAD_USER = b'\x73'  # UPLOAD Users extended
CMD_GET_DEVICEID = b'\x74'  # GET DEVICE ID
CMD_SET_DEVICEID = b'\x75'  # SET DEVICE ID
CMD_DEL_ADMIN_FLAG = b'\x3D'  # CLEAR ADMINISTRATOR FLAG
CMD_GET_EMPLOYE_ENROLL_TIME = b'\x3E'  # Get the time a employe enrols
CMD_SET_EMPLOYE_ENROLL_TIME = b'\x3F'  # Set the time a employe enrols
CMD_GET_RANDOM = b'\x76'  # Get Random Number
CMD_SET_ENCRYPT = b'\x77'  # Encrypt device type and language with random number
CMD_GET_SERIALNUMBER = b'\x24'  # GET DEVICE SERIAL NUMBER
CMD_SET_SERIALNUMBER = b'\x25'  # SET DEVICE SERIAL NUMBER
CMD_UPLOAD_FIRMWARE = b'\x10'  # WARNING! UPLOAD OF FIRMWARE AND PHOTOS/VOICE
CMD_GET_DAYLIGHT = b'\x1A'  # Get daylight saving flag and time zone
CMD_SET_DAYLIGHT = b'\x1B'  # Set daylight saving flag and time zone
CMD_GET_LANG = b'\x18'  # Get Language settings
CMD_SET_LANG = b'\x19'  # Set Language settings
CMD_EMULATE_INTERACTION = b'\x78'  # Emulate a physical interaction on the device, such as a card being scanned
CMD_GET_GPRS = b'\x16'  # Get GPRS
CMD_SET_GPRS = b'\x16'  # Set GPRS
CMD_GET_DEVICE_INFO_EXTENDED = b'\x7A'
CMD_SET_DEVICE_INFO_EXTENDED = b'\x7B'

# This are commands for legacy equipment
OA3000_CMD_GET_INDEX_MESSAGE = b'\x26'  # GET INDEX MESSAAGE FOR MODEL OA3000 ONLY
OA3000_CMD_SET_INDEX_MESSAGE = b'\x27'  # SET INDEX MESSAAGE FOR MODEL OA3000 ONLY
OA3000_CMD_GET_MESSAGES = b'\x28'  # Get Subject/Hedears of messages
OA3000_CMD_DEL_MESSAGES = b'\x29'  # Delete Subject/Hedears of messages
OA3000_CMD_GET_STATUS_SWITCHING = b'\x20'  # GET TA auto switching states
OA3000_CMD_SET_STATUS_SWITCHING = b'\x21'  # GET TA auto switching states

M761_CMD_DOWNLOAD_USERS = b'\x22'  # Model 761 Download User Database
M761_CMD_UPLOAD_USERS = b'\x22'  # Model 761 Upload User Database
M761_CMD_FILEMANAGER = b'\x12'  # Model 761 File Manager Command
M761_CMD_GET_LOG = b'\x13'  # Download Log Records

VFP_CMD_GET_SPECIAL_STATE = b'\x2F'  # GET special state, whatever that is

CMD_GET_PHOTO_AMOUNT = b'\x2A'  # Get ammount of photos
CMD_GET_PHOTO_INFO = b'\x2B'  # Get photos info
CMD_GET_PHOTO_USER = b'\x2C'  # Get user photos

T5X_CMD_GET_ADMIN = b'\x1C'  # Get admin card/password on T5X devices
T5X_CMD_SET_ADMIN = b'\x1D'  # Set admin card/password on T5X devices

T5S_CMD_GET_PUNCHCARD = b'\x7E'  # inquire information of punched card on T5S

C5_CMD_SEND_EMAIL = b'\x7F'

# RESPONSES
ACK_SUCCESS = b"\x00"  # operation successful
ACK_FAIL = b"\x01"  # operation failed
ACK_FULL = b"\x04"  # user full
ACK_EMPTY = b"\x05"  # user empty
ACK_NO_USER = b"\x06"  # user not exist
ACK_TIME_OUT = b"\x08"  # capture timeout
ACK_USER_OCCUPIED = b"\x0A"  # user already exists
ACK_FINGER_OCCUPIED = b"\x0B"  # fingerprint already exists


def makePayload(command, data='', CH=b"\x00\x00\x00\x00"):
    if len(data) < 0x190:

        # Fix size for data 2 bytes
        size = len(data)
        size2b = bytes.fromhex(format(size, '#06x').replace("0x", ""))

        request = STX + CH + command + size2b
        if size > 0x00:  # Aditional data in channel
            request = request + data

        # Add CRC16
        CRC = anvizCRC.calculateRevAnvizCRC(str(request))
        b = bytearray()
        b.append(CRC[0])
        b.append(CRC[1])
        request = request + b

        return request
    else:
        raise Exception('Data size too big')


def sendPayload(ip, port, payload):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(payload)
    response = s.recv(512)
    s.close()

    # Creating the tuple of the data
    preamble = response[0]  # 1 byte
    deviceCode = response[1:5]  # 4 bytes
    ack = response[5]  # 1 byte
    returnValue = response[6]  # 1 byte
    size = response[7:9]  # 2 bytes

    # sanity check for data integrity
    if (len(response) != (9 + size + 2)):  # 9 bytes from previous values plus size of the packet plus 2 bytes for CRC16
        raise Exception("Packet Size differs from actual size")

    data = b''
    crc = b''
    if (size > 0):
        data = response[9:(9 + size + 1)]  # start of data at 9th byte plus size of data plus 1 for the last byte
        crc = response[(9 + size + 1):]  # From end of data to the end of the array
    else:
        crc = response[9:]  # no data, so just finish with the CRC

    # return the packet
    return (preamble, deviceCode, ack, returnValue, size, data, crc)


def openDoor(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_OPENDOOR, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getDateOfDevice(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_DATE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getNetwork(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_NETWORK, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getUserRecords(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_RECORDS, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getFactoryInfoCode(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_FACTORYINFOCODE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def initUserArea(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_INIT_USERDATA, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def initSystem(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_INIT_SYSTEM, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getSchedualeBell(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_BELLINFO, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getHeadersOfMessages(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_MESSAGES_HEADERS, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getTAStateMessage(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_STATEMESSASE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getDeviceCapacity(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_CAPACITY, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getStateTable(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_CUSTOMSTATETABLE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getCOMMID(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_DEVICEID, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def clearAdminFlag(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_DEL_ADMIN_FLAG, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getRandomNumber(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_RANDOM, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getSerialNumber(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_SERIALNUMBER, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getSpecialState(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(VFP_CMD_GET_SPECIAL_STATE, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getPhotoAmount(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_PHOTO_AMOUNT, CH=CH)
    response = sendPayload(ip, port, payload)
    return response



def getAdminOrCardCredentials(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(T5X_CMD_GET_ADMIN, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getDaylight(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_DAYLIGHT, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getLanguages(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_LANG, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getGPRSSettings(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_GPRS, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getDeviceExtendedInformation(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(CMD_GET_DEVICE_INFO_EXTENDED, CH=CH)
    response = sendPayload(ip, port, payload)
    return response


def getCardInfo(ip, port=5010, CH=b"\x00\x00\x00\x00"):
    payload = makePayload(T5S_CMD_GET_PUNCHCARD, CH=CH)
    response = sendPayload(ip, port, payload)
    return response
