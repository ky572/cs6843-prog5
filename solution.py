from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def sequence(max):
  x = 0
  while True:
    yield x
    x += 1
    if x > max:
      x = 0

seq = sequence(0xffff)

def checksum(string):
# In this function we make the checksum of our packet
  csum = 0
  countTo = (len(string) // 2) * 2
  count = 0

  while count < countTo:
    thisVal = (string[count + 1]) * 256 + (string[count])
    csum += thisVal
    csum &= 0xffffffff
    count += 2

  if countTo < len(string):
    csum += (string[len(string) - 1])
    csum &= 0xffffffff

  csum = (csum >> 16) + (csum & 0xffff)
  csum = csum + (csum >> 16)
  answer = ~csum
  answer = answer & 0xffff
  answer = answer >> 8 | (answer << 8 & 0xff00)
  return answer

def compute_zeroed_checksum(type, code, ID, seqNum, data):
  myChecksum = 0

  # Make a dummy header with a 0 checksum
  # struct -- Interpret strings as packed binary data
  header = struct.pack("bbHHh", type, code, myChecksum, ID, seqNum)
  # Calculate the checksum on the data and the dummy header.
  myChecksum = checksum(header + data)

  # Get the right checksum, and put in the header

  if sys.platform == 'darwin':
    # Convert 16-bit integers from host to network  byte order
    myChecksum = htons(myChecksum) & 0xffff
  else:
    myChecksum = htons(myChecksum)

  return myChecksum

class ICMPData:
  def __init__(self, type, code, checksum, id, seq, payload):
    self.type = type
    self.code = code
    self.checksum = checksum
    self.id = id
    self.seq = seq
    self.payload = payload
    self.zeroed_checksum = None

  def validate(ID, seqNum):
    if self.zeroed_checksum is None:
      self.zeroed_checksum = compute_zeroed_checksum(self.type, self.code, self.id, self.seq, struct.pack('d', self.payload))

    return self.zeroed_checksum == self.checksum and ID == self.id and self.seq == seqNum

  def __str__(self):
    return f'Type: {self.type}\nCode: {self.code}\nChecksum: {self.checksum}\nID: {self.id}\nSeq: {self.seq}\nPayload: {self.payload}\n'

def read_icmp(bytes):
  header_size = struct.calcsize('bbHHh')
  icmp_data = struct.unpack('bbHHh', bytes[:header_size])

  return ICMPData(icmp_data[0], icmp_data[1], icmp_data[2], icmp_data[3], icmp_data[4], bytes[header_size:])

def build_request():
  seq_num = next(seq) & 0xffff
  send_time = time.time()
  myID = os.getpid() & 0xffff
  data = struct.pack("d", send_time)

  myChecksum = compute_zeroed_checksum(ICMP_ECHO_REQUEST, 0, myID, seq_num, data)

  return ICMPData(ICMP_ECHO_REQUEST, 0, myChecksum, myID, seq_num, data)


def build_packet(icmp):
  #Fill in start
  # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
  # packet to be sent was made, secondly the checksum was appended to the header and
  # then finally the complete packet was sent to the destination.

  # Make the header in a similar way to the ping exercise.
  # Append checksum to the header.

  # Don’t send the packet yet , just return the final packet in this function.

  header = struct.pack("bbHHh", icmp.type, icmp.code, icmp.checksum, icmp.id, icmp.seq)

  #Fill in end

  # So the function ending should look like this

  packet = header + icmp.payload
  return packet

def build_timeout(hops):
  return [str(hops), '*', 'Request timed out']

def build_output(hops, rtt, hostip, hostname):
  return [str(hops), f'{str(round(rtt,2))}ms', hostip, 'hostname not returnable' if hostname is None else hostname]

def get_route(hostname):
  timeLeft = TIMEOUT
  tracelist1 = [] #This is your list to use when iterating through each trace
  tracelist2 = [] #This is your list to contain all traces
  icmp = getprotobyname("icmp")
  destAddr = gethostbyname(hostname)
  reached_dest = False
  sent_times = {}

  for ttl in range(1,MAX_HOPS):
    for tries in range(TRIES):
      #Fill in start
      # Make a raw socket named mySocket
      mySocket = socket(AF_INET, SOCK_RAW, icmp)
      #Fill in end

      mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
      #mySocket.settimeout(TIMEOUT)
      try:
        req = build_request()
        d = build_packet(req)
        mySocket.sendto(d, (destAddr, 0))
        send_time = time.time()
        sent_times[req.seq] = send_time
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
          #Fill in start
          #You should add the list above to your all traces list
          tracelist2.append(build_timeout(ttl))
          break
          #Fill in end
        recvPacket, addr = mySocket.recvfrom(1024)
        timeReceived = time.time()
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
          #Fill in start
          #You should add the list above to your all traces list
          tracelist2.append(build_timeout(ttl))
          break
          #Fill in end
      except timeout:
        continue

      else:
        #Fill in start
        #Fetch the icmp type from the IP packet
        icmp_data = read_icmp(recvPacket[20:])
        types = icmp_data.type
        #Fill in end
        try: #try to fetch the hostname
          #Fill in start
          hop_name = gethostbyaddr(addr[0])[0]
          #Fill in end
        except herror:   #if the host does not provide a hostname
          #Fill in start
          hop_name = None
          #Fill in end

        if types == 11 or types == 3:
          sent_icmp = read_icmp(icmp_data.payload[20:])
          timeSent = sent_times[sent_icmp.seq]
          delay = (timeReceived - timeSent)*1000
          #Fill in start
          #You should add your responses to your lists here
          tracelist2.append(build_output(ttl, delay, addr[0], hop_name))
          #Fill in end
        elif types == 0:
          timeSent = sent_times[icmp_data.seq]
          delay = (timeReceived - timeSent)*1000
          tracelist2.append(build_output(ttl, delay, addr[0], hop_name))
        else:
          #Fill in start
          continue
          #If there is an exception/error to your if statements, you should append that to your list here
          #Fill in end

        if addr[0] == destAddr:
          reached_dest = True

        break
      finally:
        mySocket.close()

    if reached_dest is True:
      break

  return tracelist2

if __name__ == '__main__':
    result = get_route("google.co.il")
    print(result)
