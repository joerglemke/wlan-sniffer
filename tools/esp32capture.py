import serial
import sys
import io
import os
import subprocess
import signal
import time
import win32.win32pipe
import win32.win32file

# com6 channel=1 filtermac=fc:51:a4:cf:f6:4e

if len(sys.argv) < 2:
    print("usage: esp32capture serialport [channel=CH] [filtermac=XX:XX:XX:XX:XX:XX] [allbeacons]")
    sys.exit(1)

serialport = sys.argv[1]
configCommands = sys.argv[2:]
# channel = sys.argv[2]
# filtermac = sys.argv[3] if len(sys.argv) >= 4 else None

try:
    ser = serial.Serial(serialport, 115200)
except:
    print("serial port ",  serialport, " cannot be opened. Is the ESP32 connected to USB?")
    sys.exit(1)

ser.timeout = 1
ser.dtr = False
ser.rts = True
ser.rts = False

def sendCommand(cmd):
    print (": ", cmd)
    ser.write(bytes(cmd + "\r\n", "ascii"))

check = 0
while check == 0:
    line = ser.readline()
    line = line[0:len(line)-2]
    # print("ser: ", line)
    if line.startswith(b"ESP32PCAP"):
        check = 1
        args = line.split(b" ")
        for arg in args[1:]:
            pair = arg.split(b"=")
            key = pair[0]
            if len(pair) == 2:
                val = pair[1]
            else:
                val = ""
            # print("arg: ", key, " -> ", val)
            if key == b"baudrate":
                baudrate = int(val)

# print("baudrate is ", baudrate)

# f = open("c:/temp/x.pcap", "wb")

pipe = win32.win32pipe.CreateNamedPipe(
    r'\\.\pipe\wireshark',
    win32.win32pipe.PIPE_ACCESS_OUTBOUND,
    win32.win32pipe.PIPE_TYPE_MESSAGE | win32.win32pipe.PIPE_WAIT,
    1, 65536, 65536,
    300,
    None)
wireshark_cmd=['C:\Program Files\Wireshark\Wireshark.exe', r'-i\\.\pipe\wireshark','-k']
proc=subprocess.Popen(wireshark_cmd)
win32.win32pipe.ConnectNamedPipe(pipe, None)

ser.write(b"\r\n")
for cmd in configCommands:
    sendCommand(cmd)
# sendCommand("allbeacons")
# if filtermac:
#     sendCommand("filtermac " + filtermac)
# sendCommand("channel " + str(channel))

sendCommand("start=" + str(int(time.time())))
line = ser.readline()
# print("starting: ", line)
if not line.startswith(b"SNIFFMODE=starting"):
    print("unexpected starting prompt: ", line)    
    sys.exit(1)

ser.baudrate = baudrate

try:
    while True:
        line = ser.readline()
        if (len(line) > 0):
            break;
    if not line.startswith(b"SNIFFMODE=running"):
        print("unexpected running prompt: ", line)    
        while True:
            line = ser.readline()
            print("error: ", line)
    # print("started: ", line)
    # while True:
    #     line = ser.readline()
    #     if len(line) > 0:
    #         print(": ", line)
    sniffing = True
except KeyboardInterrupt:
    print("Stopping...")

if sniffing:
    try:
        while True:
            block = ser.read(4096)
            if len(block) > 0:
                # f.write(block)
                win32.win32file.WriteFile(pipe, block)
                win32.win32file.FlushFileBuffers(pipe)
    except win32.win32file.error:
        print("Wireshark stopped")
        ser.dtr = True
    except KeyboardInterrupt:
        print("Stopping...")
        ser.dtr = True
        while True:
            block = ser.read(4096)
            if len(block) > 0:
                win32.win32file.WriteFile(pipe, block)
                win32.win32file.FlushFileBuffers(pipe)
            else:
                break
    finally:
        time.sleep(1)
        ser.dtr = False

# f.close()
ser.close()
