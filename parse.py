# -*- coding: utf-8 -*-
import sys
import struct
import json

strings = []

def GetDynamicWireFormat(data, start, end):
    wire_type = data[start] & 0x7
    firstByte = data[start]
    if (firstByte & 0x80) == 0:
        field_number = (firstByte >> 3)
        return (start + 1, wire_type, field_number)
    else:
        byteList = []
        pos = 0
        while True:
            if start + pos >= end:
                return (None, None, None)
            oneByte = data[start + pos]
            byteList.append(oneByte & 0x7F)
            pos += 1
            if oneByte & 0x80 == 0x0:
                break

        newStart = start + pos

        index = len(byteList) - 1
        field_number = 0
        while index >= 0:
            field_number = (field_number << 0x7) + byteList[index]
            index -= 1

        field_number = (field_number >> 3)
        return (newStart, wire_type, field_number)

def RetrieveInt(data, start, end):
    pos = 0
    byteList = []
    while True:
        if start + pos >= end:
            return (None, None, False)
        oneByte = data[start + pos]
        byteList.append(oneByte & 0x7F)
        pos += 1
        if oneByte & 0x80 == 0x0:
            break

    newStart = start + pos

    index = len(byteList) - 1
    num = 0
    while index >= 0:
        num = (num << 0x7) + byteList[index]
        index -= 1
    return (num, newStart, True)

def ParseRepeatedField(data, start, end, message, depth=0):
    while start < end:
        num, start, success = RetrieveInt(data, start, end)
        if not success:
            return False
        message.append(num)
    return True

def ParseData(data, start, end, messages, depth=0):
    global strings
    ordinary = 0
    while start < end:
        start, wire_type, field_number = GetDynamicWireFormat(data, start, end)
        if start is None:
            return False

        if wire_type == 0x00:  # Varint
            num, start, success = RetrieveInt(data, start, end)
            if not success:
                return False

            if depth != 0:
                strings.append('\t' * depth)
            strings.append(f"({field_number}) Varint: {num}\n")
            messages[f'{field_number:02d}:{ordinary:02d}:Varint'] = num
            ordinary += 1

        elif wire_type == 0x01:  # 64-bit
            num = 0
            pos = 7
            while pos >= 0:
                if start + pos >= end:
                    return False
                num = (num << 8) + data[start + pos]
                pos -= 1

            start += 8
            try:
                floatNum = struct.unpack('d', struct.pack('q', int(hex(num), 16)))[0]
            except:
                floatNum = None

            if depth != 0:
                strings.append('\t' * depth)
            if floatNum is not None:
                strings.append(f"({field_number}) 64-bit: 0x{num:x} / {floatNum}\n")
                messages[f'{field_number:02d}:{ordinary:02d}:64-bit'] = floatNum
            else:
                strings.append(f"({field_number}) 64-bit: 0x{num:x}\n")
                messages[f'{field_number:02d}:{ordinary:02d}:64-bit'] = num

            ordinary += 1

        elif wire_type == 0x02:  # Length-delimited
            curStrIndex = len(strings)
            stringLen, start, success = RetrieveInt(data, start, end)
            if not success:
                return False
            if depth != 0:
                strings.append('\t' * depth)
            strings.append(f"({field_number}) embedded message:\n")
            messages[f'{field_number:02d}:{ordinary:02d}:embedded message'] = {}
            if start + stringLen > end:
                del strings[curStrIndex + 1:]
                messages.pop(f'{field_number:02d}:{ordinary:02d}:embedded message', None)
                return False

            ret = ParseData(data, start, start + stringLen, messages[f'{field_number:02d}:{ordinary:02d}:embedded message'], depth + 1)
            if not ret:
                del strings[curStrIndex + 1:]
                messages.pop(f'{field_number:02d}:{ordinary:02d}:embedded message', None)
                if depth != 0:
                    strings.append('\t' * depth)

                strings.append(f"({field_number}) repeated:\n")
                try:
                    strings.append(f"({field_number}) string: {data[start:start + stringLen].decode('utf-8')}\n")
                    messages[f'{field_number:02d}:{ordinary:02d}:string'] = data[start:start + stringLen].decode('utf-8')
                except:
                    if depth != 0:
                        strings.append('\t' * depth)

                    strings.append(f"({field_number}) repeated:\n")
                    messages[f'{field_number:02d}:{ordinary:02d}:repeated'] = []
                    ret = ParseRepeatedField(data, start, start + stringLen, messages[f'{field_number:02d}:{ordinary:02d}:repeated'], depth + 1)
                    if not ret:
                        del strings[curStrIndex + 1:]
                        messages.pop(f'{field_number:02d}:{ordinary:02d}:repeated', None)
                        hexStr = ':'.join(f'0x{x:02x}' for x in data[start:start + stringLen])
                        strings.append(f"({field_number}) bytes: {hexStr}\n")
                        messages[f'{field_number:02d}:{ordinary:02d}:bytes'] = hexStr

            ordinary += 1
            start += stringLen

        elif wire_type == 0x05:  # 32-bit
            num = 0
            pos = 3
            while pos >= 0:
                if start + pos >= end:
                    return False
                num = (num << 8) + data[start + pos]
                pos -= 1

            start += 4
            try:
                floatNum = struct.unpack('f', struct.pack('i', int(hex(num), 16)))[0]
            except:
                floatNum = None

            if depth != 0:
                strings.append('\t' * depth)
            if floatNum is not None:
                strings.append(f"({field_number}) 32-bit: 0x{num:x} / {floatNum}\n")
                messages[f'{field_number:02d}:{ordinary:02d}:32-bit'] = floatNum
            else:
                strings.append(f"({field_number}) 32-bit: 0x{num:x}\n")
                messages[f'{field_number:02d}:{ordinary:02d}:32-bit'] = num 

            ordinary += 1

        else:
            return False

    return True

def ParseProto(fileName):
    with open(fileName, "rb") as f:
        data = f.read()
    size = len(data)

    messages = {}
    ParseData(data, 0, size, messages)

    return messages

def GenValueList(value):
    valueList = []
    while value >= 0:
        oneByte = (value & 0x7F)
        value = (value >> 0x7)
        if value > 0:
            oneByte |= 0x80
        valueList.append(oneByte)
        if value == 0:
            break
    return valueList

def WriteValue(value, output):
    byteWritten = 0
    while value >= 0:
        oneByte = (value & 0x7F)
        value = (value >> 0x7)
        if value > 0:
            oneByte |= 0x80
        output.append(oneByte)
        byteWritten += 1
        if value == 0:
            break
    return byteWritten

def WriteVarint(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x00
    byteWritten += WriteValue(wireFormat, output)
    while value >= 0:
        oneByte = (value & 0x7F)
        value = (value >> 0x7)
        if value > 0:
            oneByte |= 0x80
        output.append(oneByte)
        byteWritten += 1
        if value == 0:
            break
    return byteWritten

def Write64bitFloat(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x01
    byteWritten += WriteValue(wireFormat, output)
    
    bytesStr = struct.pack('d', value)
    output.extend(bytesStr)
    byteWritten += len(bytesStr)
    
    return byteWritten

def Write64bit(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x01
    byteWritten += WriteValue(wireFormat, output)
    
    for i in range(8):
        output.append(value & 0xFF)
        value >>= 8
        byteWritten += 1
    return byteWritten

def Write32bitFloat(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x05
    byteWritten += WriteValue(wireFormat, output)
    
    bytesStr = struct.pack('f', value)
    output.extend(bytesStr)
    byteWritten += len(bytesStr)
    
    return byteWritten

def Write32bit(field_number, value, output):
    byteWritten = 0
    wireFormat = (field_number << 3) | 0x05
    byteWritten += WriteValue(wireFormat, output)
    
    for i in range(4):
        output.append(value & 0xFF)
        value >>= 8
        byteWritten += 1
    return byteWritten

def WriteRepeatedField(message, output):
    byteWritten = 0
    for v in message:
        byteWritten += WriteValue(v, output)
    return byteWritten

def Decode(binary):
    messages = {}
    ret = ParseData(binary, 0, len(binary), messages)

    if not ret:
        return False

    return messages

def ReEncode(messages, output):
    byteWritten = 0
    for key in sorted(messages.keys(), key=lambda x: int(x.split(':')[1])):
        keyList = key.split(':')
        field_number = int(keyList[0])
        wire_type = keyList[2]
        value = messages[key]

        if wire_type == 'Varint':
            byteWritten += WriteVarint(field_number, value, output)
        elif wire_type == '32-bit':
            if isinstance(value, float):
                byteWritten += Write32bitFloat(field_number, value, output)
            else:
                byteWritten += Write32bit(field_number, value, output)
        elif wire_type == '64-bit':
            if isinstance(value, float):
                byteWritten += Write64bitFloat(field_number, value, output)
            else:
                byteWritten += Write64bit(field_number, value, output)
        elif wire_type == 'embedded message':
            wireFormat = (field_number << 3) | 0x02
            byteWritten += WriteValue(wireFormat, output)
            index = len(output)
            tmpByteWritten = ReEncode(messages[key], output)
            valueList = GenValueList(tmpByteWritten)
            listLen = len(valueList)
            output[index:index] = valueList
            byteWritten += tmpByteWritten + listLen
        elif wire_type == 'repeated':
            wireFormat = (field_number << 3) | 0x02
            byteWritten += WriteValue(wireFormat, output)
            index = len(output)
            tmpByteWritten = WriteRepeatedField(messages[key], output)
            valueList = GenValueList(tmpByteWritten)
            listLen = len(valueList)
            output[index:index] = valueList
            byteWritten += tmpByteWritten + listLen
        elif wire_type == 'string':
            wireFormat = (field_number << 3) | 0x02
            byteWritten += WriteValue(wireFormat, output)
            bytesStr = list(value.encode('utf-8'))
            byteWritten += WriteValue(len(bytesStr), output)
            output.extend(bytesStr)
            byteWritten += len(bytesStr)
        elif wire_type == 'bytes':
            wireFormat = (field_number << 3) | 0x02
            byteWritten += WriteValue(wireFormat, output)
            bytesStr = list(map(lambda x: int(x, 16), value.split(':')))
            byteWritten += WriteValue(len(bytesStr), output)
            output.extend(bytesStr)
            byteWritten += len(bytesStr)
            
    return byteWritten


def SaveModification(messages, fileName):
    output = []
    ReEncode(messages, output)
    with open(fileName, 'wb') as f:
        f.write(bytearray(output))

# if __name__ == "__main__":
#     if sys.argv[1] == "dec":
#         messages = ParseProto('tmp.pb')

#         with open('tmp.json', 'w', encoding='utf-8') as f:
#             json.dump(messages, f, indent=4, sort_keys=True, ensure_ascii=False)

#     elif sys.argv[1] == "enc":
#         with open('tmp.json', 'r', encoding='utf-8') as f:
#             messages = json.load(f)
        
#         SaveModification(messages, "tmp.pb")

#     else:
#         messages = ParseProto(sys.argv[1])

#         print(json.dumps(messages, indent=4, sort_keys=True, ensure_ascii=False))

#         # modify any field you like
#         # messages['01:00:embedded message']['01:00:string'] = "あなた"

#         with open('tmp.json', 'w', encoding='utf-8') as f:
#             json.dump(messages, f, indent=4, sort_keys=True, ensure_ascii=False)

#         with open('tmp.json', 'r', encoding='utf-8') as f:
#             messages = json.load(f)

#         SaveModification(messages, "modified")
