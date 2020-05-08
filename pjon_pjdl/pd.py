##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2017 Kevin Redon <kingkevin@cuvoodoo.info>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd

class SamplerateError(Exception):
    pass

# Timing values in us for the signal at regular and overdrive speed.
timing = {
    'RSTL': {
        'min': {
            False: 480.0,
            True: 48.0,
        },
        'max': {
            False: 960.0,
            True: 80.0,
        },
    },
    'RSTH': {
        'min': {
            False: 480.0,
            True: 48.0,
        },
    },
    'PDH': {
        'min': {
            False: 15.0,
            True: 2.0,
        },
        'max': {
            False: 60.0,
            True: 6.0,
        },
    },
    'PDL': {
        'min': {
            False: 60.0,
            True: 8.0,
        },
        'max': {
            False: 240.0,
            True: 24.0,
        },
    },
    'SLOT': {
        'min': {
            False: 60.0,
            True: 6.0,
        },
        'max': {
            False: 120.0,
            True: 16.0,
        },
    },
    'REC': {
        'min': {
            False: 1.0,
            True: 1.0,
        },
    },
    'LOWR': {
        'min': {
            False: 1.0,
            True: 1.0,
        },
        'max': {
            False: 15.0,
            True: 2.0,
        },
    },
}

class Decoder(srd.Decoder):
    api_version = 3
    id = 'pjon-pjdl'
    name = 'PJON PJDL'
    longname = 'PJON PJDL (Padded Jittering Data Link)'
    desc = 'Two way communication on one wire.'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['pjdl_link']
    channels = (
        {'id': 'data', 'name': 'Data', 'desc': 'PJON Data Line'},
    )
    options = (
        {'id': 'mode', 'desc': 'Which PJON mode to use',
            'default': '1', 'values': ('1', '2', '3', '4')},
    )
    annotations = (
        ('sync', 'Sync'),
        ('bit', 'Bit'),
        ('byte', 'Byte'),
        ('frame', 'Frame'),
        ('info', 'Info'),
    )
    annotation_rows = (
        ('bits', 'Bits', (0,1,)),
        ('bytes', 'Bytes', (2,)),
        ('frame', 'Frames', (3,)),
        ('note', 'Node', (4,)),
    )

    def __init__(self):
        self.samplerate = None
        self.state = 'INITIAL'
        self.present = 0
        self.bit = 0
        self.bit_count = -1
        self.command = 0
        self.overdrive = False
        self.fall = 0
        self.rise = 0

    def start(self):
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.fall = 0
        self.rise = 0
        self.bit_count = -1




    def putm(self, data):
        self.put(0, 0, self.out_ann, data)

    def putpfs(self, data):
        self.put(self.fall, self.samplenum, self.out_python, data)

    def putfs(self, data):
        self.put(self.fall, self.samplenum, self.out_ann, data)

    def putfr(self, data):
        self.put(self.fall, self.rise, self.out_ann, data)

    def putprs(self, data):
        self.put(self.rise, self.samplenum, self.out_python, data)

    def putrs(self, data):
        self.put(self.rise, self.samplenum, self.out_ann, data)

    def checks(self):
        # Check if samplerate is appropriate.
        if self.options['mode'] == '1':
            if self.samplerate < 2000000:
                self.putm([3, ['Sampling rate is too low. Must be above ' +
                               '2MHz for proper pjon mode 1 decoding.']])
            elif self.samplerate < 5000000:
                self.putm([3, ['Sampling rate is suggested to be above 5MHz ' +
                               'for pjon mode 1 decoding.']])
        else:
            if self.samplerate < 2000000:
                self.putm([3, ['Sampling rate is too low. Must be above ' +
                               '2MHz for proper decoding.']])
            elif self.samplerate < 5000000:
                self.putm([3, ['Sampling rate is suggested to be above 5MHz ' +
                               'for pjon decoding.']])

    def metadata(self, key, value):
        if key != srd.SRD_CONF_SAMPLERATE:
            return
        self.samplerate = value
        self.SWBB_BIT_WIDTH = int(float(44)/1000000.0*self.samplerate)
        self.SWBB_BIT_SPACER = int(float(112)/1000000.0*self.samplerate)
        self.SWBB_ACCEPTANCE = int(float(56)/1000000.0*self.samplerate)
        self.SWBB_RESPONSE_TIMEOUT = int(float(1500)/1000000.0*self.samplerate)
        self.SWBB_COLLISION_DELAY =  int(float(16)/1000000.0*self.samplerate)

        # No header present (unacceptable value used)
        self.HEADER_NO_HEADER = 0b01001000
        #0 - Local network
        #1 - Shared  network */
        self.HEADER_SHARE_MODE_BIT = 0b00000001
        # 0 - No info inclusion
        #1 - Local:  Sender device id included
        #Shared: Sender device id + Sender bus id
        self.HEADER_TX_INFO_BIT = 0b00000010
        # 0 - Synchronous acknowledgement disabled
        #1 - Synchronous acknowledgement enabled
        self.HEADER_ACK_REQ_BIT = 0b00000100
        # 0 - Asynchronous acknowledgement disabled
        # 1 - Asynchronous acknowledgement enabled
        self.HEADER_ACK_MODE_BIT = 0b00001000
        # 0 - No port id contained
        # 1 - Port id contained (2 bytes integer)
        self.HEADER_PORT_BIT = 0b00010000
        # 0 - CRC8 (1 byte) included at the end of the packet
        # 1 - CRC32 (4 bytes) included at the end of the packet
        self.HEADER_CRC_BIT = 0b00100000
        # 0 - 1 byte long (max 255 bytes)
        # 1 - 2 bytes long (max 65535 bytes)
        self.HEADER_EXT_LEN_BIT = 0b01000000
        # 0 - Packet id not present
        # 1 - Packet id present
        self.HEADER_PACKET_ID_BIT = 0b10000000

    def wait_falling_timeout(self, start, t):
        # Wait until either a falling edge is seen, and/or the specified
        # number of samples have been skipped (i.e. time has passed).

        cnt = int(t)
        samples_to_skip = (start + cnt) - self.samplenum
        samples_to_skip = samples_to_skip if (samples_to_skip > 0) else 0

        ret = self.wait([{0: 'f'}, {'skip': samples_to_skip}])
        self.fall = self.samplenum

        return ret


    # def wait_falling_timeout(self, start, t):
    #     # Wait until either a falling edge is seen, and/or the specified
    #     # number of samples have been skipped (i.e. time has passed).
    #     cnt = int((t[self.overdrive] / 1000000.0) * self.samplerate)
    #     samples_to_skip = (start + cnt) - self.samplenum
    #     samples_to_skip = samples_to_skip if (samples_to_skip > 0) else 0
    #     return self.wait([{0: 'f'}, {'skip': samples_to_skip}])


    def wait_rising_timeout(self, start, t):
        # Wait until either a falling edge is seen, and/or the specified
        # number of samples have been skipped (i.e. time has passed).
        cnt = int(t)
        samples_to_skip = (start + cnt) - self.samplenum
        samples_to_skip = samples_to_skip if (samples_to_skip > 0) else 0
        ret = self.wait([{0: 'r'}, {'skip': samples_to_skip}])

        self.rise = self.samplenum
        return ret



    def decode(self):
        if not self.samplerate:
            raise SamplerateError('Cannot decode without samplerate.')
        self.checks()
        while True:
            # State machine.
            if self.state == 'INITIAL': # Unknown initial state.
                # Wait until we reach the idle high state.
#                self.wait({0: 'h'})
#                self.rise = self.samplenum
                self.state = 'START_SYNC'

            elif self.state == 'START_SYNC': # Idle high state.
                self.syncs = 0
                self.state = 'SYNC'

            elif self.state == 'SYNC' or self.state == 'SYNC_READ_BYTE': # Idle high state.


                sync_wait_start = self.samplenum
                # Wait for rising edge of sync start.
                self.wait([{0: 'r'},{0: 'h'}])
                sync_start = self.rise = self.samplenum

                #self.put(sync_wait_start, self.samplenum-1, self.out_ann, [3, ['WaitForSync', 'Wait']])

                # Wait for falling edge.
                self.wait([{0: 'f'}])

                self.wait_falling_timeout(self.rise, self.SWBB_ACCEPTANCE*1.1)
                self.fall = self.samplenum

                # Get time since last rising edge.
                time = (self.fall - self.rise)
                # self.put(sync_start, self.samplenum, self.out_python, [0, ['zSync: %d' % self.bit, '%d' % self.bit]])

                if self.rise <= 0 or time < 1:
                    continue

                if time < self.SWBB_ACCEPTANCE:
                    self.put(sync_start, self.samplenum, self.out_ann, [1, ['SyncHighToShort', 'SyncHighToShort']])
                    continue
                if time > self.SWBB_BIT_SPACER*1.2:
                    self.put(sync_start, self.samplenum, self.out_ann, [1, ['SyncHighToLong', 'SyncHighToLong']])
                    continue
                else:
                    self.put(sync_start, self.samplenum, self.out_ann, [1, ['SyncHigh', 'High']])

                self.wait_rising_timeout(self.fall, self.SWBB_BIT_WIDTH)
                self.rise = self.samplenum
                self.syncs = self.syncs + 1

                if self.fall > 0 and (self.rise-self.fall) >= self.SWBB_BIT_WIDTH:
                    if self.state == 'SYNC_READ_BYTE':
                        self.put(sync_start, self.samplenum, self.out_ann, [0, ['Sync', 'S']])
                    else:
                        self.put(sync_start, self.samplenum, self.out_ann, [2, ['Frame Sync: %d' % self.syncs, 'S %d' % self.syncs]])

                else:
                    self.put(sync_start, self.samplenum, self.out_ann, [3, ['Sync Fail', '!S %d' % (self.rise-self.fall)]])

                if self.state == 'SYNC' and self.syncs == 3:
                    self.syncs = 0
                    self.packet_pos = 0
                    self.state = 'SYNC_READ_BYTE'
                    self.packet_bytes = []
                    self.packet_bytes_times = []
                    self.packet_field = 'To'
                    self.packet_field_start = self.samplenum
                    self.packet_flags = 0
                elif self.state == 'SYNC_READ_BYTE' and self.syncs == 1:
                    self.syncs = 0
                    self.bit_num = 0
                    self.byte_val = 0
                    self.byte_start = self.samplenum
                    self.state = 'READ_BYTE'

            elif self.state == 'READ_BYTE': # Idle high state.
                ret = self.wait({'skip': int(self.SWBB_BIT_WIDTH/2)-1})
                bit_val = ret[0]
                bit_center = self.samplenum
                self.byte_val = self.byte_val | bit_val << self.bit_num;
                self.wait([{'skip': int(self.SWBB_BIT_WIDTH/2)}])

                self.put(bit_center, bit_center, self.out_ann, [0, ['Bit: %d-%d' % (self.bit_num, bit_val) , '%d' % bit_val]])

                self.bit_num = self.bit_num+1

                if self.bit_num == 8:
                    self.packet_bytes.append(self.byte_val)
                    self.packet_bytes_times.append(self.samplenum)
                    self.state = 'SYNC_READ_BYTE'

                    keep_parsing = True
                    while keep_parsing:

                        if self.packet_field == 'To':
                            self.put(self.byte_start, self.samplenum, self.out_ann, [3, ['To: %d' % self.byte_val, '%d' % self.byte_val]])
                            self.packet_field = 'Flags'
                            self.packet_field_start = self.samplenum + 1

                        elif self.packet_field == 'Flags':
                            self.packet_flags = self.byte_val

                            if self.packet_flags & self.HEADER_EXT_LEN_BIT == self.HEADER_EXT_LEN_BIT:
                                self.is_ext_len = True
                            else:
                                self.is_ext_len = False

                            if self.packet_flags & self.HEADER_SHARE_MODE_BIT == self.HEADER_SHARE_MODE_BIT:
                                self.is_shared_mode_packet = True
                            else:
                                self.is_shared_mode_packet = False

                            if self.packet_flags & self.HEADER_TX_INFO_BIT == self.HEADER_TX_INFO_BIT:
                                self.sender_id_included = True
                            else:
                                self.sender_id_included = False

#                            self.put(self.packet_field_start, self.samplenum, self.out_ann, [3, ['Flags: %d' % self.byte_val, '%d' % self.byte_val]])


                            flag_name = 'SHARED'
                            flag_bit = self.HEADER_SHARE_MODE_BIT
                            flag_val = 1 if self.byte_val & flag_bit == flag_bit else 0
                            flag_bit_no = 7
                            self.put(int(self.samplenum-((flag_bit_no+1)*self.SWBB_BIT_WIDTH)), int(self.samplenum-((flag_bit_no)*self.SWBB_BIT_WIDTH)), self.out_ann, [3, ['%s %d' % (flag_name, flag_val), flag_name]])

                            flag_name = 'TX_INFO'
                            flag_bit = self.HEADER_TX_INFO_BIT
                            flag_val = 1 if self.byte_val & flag_bit == flag_bit else 0
                            flag_bit_no = 6
                            self.put(int(self.samplenum-((flag_bit_no+1)*self.SWBB_BIT_WIDTH)), int(self.samplenum-((flag_bit_no)*self.SWBB_BIT_WIDTH)), self.out_ann, [3, ['%s %d' % (flag_name, flag_val), flag_name]])

                            flag_name = 'ACK_REQ'
                            flag_bit = self.HEADER_ACK_REQ_BIT
                            flag_val = 1 if self.byte_val & flag_bit == flag_bit else 0
                            flag_bit_no = 5
                            self.put(int(self.samplenum-((flag_bit_no+1)*self.SWBB_BIT_WIDTH)), int(self.samplenum-((flag_bit_no)*self.SWBB_BIT_WIDTH)), self.out_ann, [3, ['%s %d' % (flag_name, flag_val), flag_name]])

                            flag_name = 'ACK_MODE'
                            flag_bit = self.HEADER_ACK_MODE_BIT
                            flag_val = 1 if self.byte_val & flag_bit == flag_bit else 0
                            flag_bit_no = 4
                            self.put(int(self.samplenum-((flag_bit_no+1)*self.SWBB_BIT_WIDTH)), int(self.samplenum-((flag_bit_no)*self.SWBB_BIT_WIDTH)), self.out_ann, [3, ['%s %d' % (flag_name, flag_val), flag_name]])

                            flag_name = 'PORT'
                            flag_bit = self.HEADER_PORT_BIT
                            flag_val = 1 if self.byte_val & flag_bit == flag_bit else 0
                            flag_bit_no = 3
                            self.put(int(self.samplenum-((flag_bit_no+1)*self.SWBB_BIT_WIDTH)), int(self.samplenum-((flag_bit_no)*self.SWBB_BIT_WIDTH)), self.out_ann, [3, ['%s %d' % (flag_name, flag_val), flag_name]])

                            flag_name = 'CRC'
                            flag_bit = self.HEADER_CRC_BIT
                            flag_val = 1 if self.byte_val & flag_bit == flag_bit else 0
                            flag_bit_no = 2
                            self.put(int(self.samplenum-((flag_bit_no+1)*self.SWBB_BIT_WIDTH)), int(self.samplenum-((flag_bit_no)*self.SWBB_BIT_WIDTH)), self.out_ann, [3, ['%s %d' % (flag_name, flag_val), flag_name]])

                            flag_name = 'EXT_LEN'
                            flag_bit = self.HEADER_EXT_LEN_BIT
                            flag_val = 1 if self.byte_val & flag_bit == flag_bit else 0
                            flag_bit_no = 1
                            self.put(int(self.samplenum-((flag_bit_no+1)*self.SWBB_BIT_WIDTH)), int(self.samplenum-((flag_bit_no)*self.SWBB_BIT_WIDTH)), self.out_ann, [3, ['%s %d' % (flag_name, flag_val), flag_name]])

                            flag_name = 'PKT_ID'
                            flag_bit = self.HEADER_PACKET_ID_BIT
                            flag_val = 1 if self.byte_val & flag_bit == flag_bit else 0
                            flag_bit_no = 0
                            self.put(int(self.samplenum-((flag_bit_no+1)*self.SWBB_BIT_WIDTH)), int(self.samplenum-((flag_bit_no)*self.SWBB_BIT_WIDTH)), self.out_ann, [3, ['%s %d' % (flag_name, flag_val), flag_name]])

                            self.packet_field = 'Payload Len'
                            self.packet_field_start = self.samplenum + 1
                            self.packet_payload_len = []

                        elif self.packet_field == 'Payload Len':
                            self.packet_payload_len.append(self.byte_val)

                            if self.packet_flags & self.HEADER_EXT_LEN_BIT == self.HEADER_EXT_LEN_BIT:
                                if len(self.packet_payload_len) == 2:
                                    self.packet_len = self.packet_payload_len[0]<<8|self.packet_payload_len[1];
                                    self.put(self.packet_bytes_times[self.packet_pos-2], self.samplenum, self.out_ann, [3, ['Len: %d' % self.packet_len, '%d' % self.packet_len]])
                                    self.packet_field = "HeaderCRC"
                            else:
                                self.packet_len = self.byte_val
                                self.put(self.packet_bytes_times[self.packet_pos-1], self.samplenum, self.out_ann, [3, ['Len: %d' % self.packet_len, '%d' % self.packet_len]])
                                self.packet_field = "HeaderCRC"

                        elif self.packet_field == 'HeaderCRC':
                            self.put(self.packet_bytes_times[self.packet_pos-1], self.samplenum, self.out_ann, [3, ['CRC8: %d' % self.byte_val, '%d' % self.byte_val]])
                            self.packet_field = "Maybe Port"

                        elif self.packet_field == 'Maybe Port':
                            if self.packet_flags & self.HEADER_PORT_BIT == self.HEADER_PORT_BIT:
                                self.packet_field = "Port"
                                self.port_bytes = []
                                self.port_field_start = self.samplenum
                            else:
                                self.packet_field = "Maybe ToNetworkId"

                        elif self.packet_field == 'Port':
                            self.port_bytes.append(self.byte_val)
                            if len(self.port_bytes) == 2:
                                port = self.port_bytes[0]<<8|self.port_bytes[1];
                                self.put(self.port_field_start, self.samplenum, self.out_ann, [3, ['Port: %d' % port, '%d' % port]])
                                self.packet_field = "Maybe ToNetworkId"

                        elif self.packet_field == 'Maybe ToNetworkId':
                            if self.is_shared_mode_packet:
                                self.packet_field = 'ToNetworkId'
                                self.packet_field_start = self.samplenum + 1
                                self.packet_field_bytes = []
                            else:
                                self.packet_field = 'Maybe FromId'

                        elif self.packet_field == 'ToNetworkId':
                            self.packet_field_bytes.append(self.byte_val)
                            if len(self.packet_field_bytes) == 4:
                                addr_str = '0x%x%x%x%x' % (self.packet_field_bytes[0],self.packet_field_bytes[1],self.packet_field_bytes[2],self.packet_field_bytes[3])
                                self.put(self.packet_field_start, self.samplenum, self.out_ann, [3, ['To Net: %s' % addr_str, '%s' % addr_str]])
                                self.packet_field = "Maybe FromNetworkId"

                        elif self.packet_field == 'Maybe FromNetworkId':
                            self.packet_field_start = self.samplenum + 1
                            if self.is_shared_mode_packet and self.sender_id_included:
                                self.packet_field = 'FromNetworkId'
                                self.packet_field_start = self.samplenum + 1
                                self.packet_field_bytes = []
                            else:
                                self.packet_field = 'Maybe FromId'

                        elif self.packet_field == 'FromNetworkId':
                            self.packet_field_bytes.append(self.byte_val)
                            if len(self.packet_field_bytes) == 4:
                                addr_str = '0x%x%x%x%x' % (self.packet_field_bytes[0],self.packet_field_bytes[1],self.packet_field_bytes[2],self.packet_field_bytes[3])
                                self.put(self.packet_field_start, self.samplenum, self.out_ann, [3, ['From Net: %s' % addr_str, '%s' % addr_str]])
                                self.packet_field = "FromId"

                        elif self.packet_field == 'Maybe FromId':
                            self.packet_field_start = self.samplenum + 1
                            if self.sender_id_included:
                                self.packet_field = "FromId"
                            else:
                                self.packet_field = "Maybe PacketId"

                        elif self.packet_field == 'FromId':
                            self.put(self.packet_bytes_times[self.packet_pos-1], self.samplenum, self.out_ann, [3, ['From: %d' % self.byte_val, '%d' % self.byte_val]])
                            self.packet_field = 'Maybe PacketId'

                        elif self.packet_field == 'Maybe PacketId':
                            if self.packet_flags & self.HEADER_PACKET_ID_BIT == self.HEADER_PACKET_ID_BIT:
                                self.packet_field = "PacketId"
                            else:
                                self.packet_field = 'Maybe Payload'

                        elif self.packet_field == 'PacketId':
                            self.put(self.packet_bytes_times[self.packet_pos-1], self.samplenum, self.out_ann, [3, ['PacketId: %d' % self.byte_val, '%d' % self.byte_val]])
                            self.packet_field = 'Maybe Payload'

                        elif self.packet_field == 'Maybe Payload':
                            self.packet_payload_start = self.samplenum + 1
                            self.packet_payload_bytes = []
                            self.packet_field = 'Payload'

                        elif self.packet_field == 'Payload':
                            self.packet_payload_bytes.append(self.byte_val)

                            crc_len = 4  if self.packet_flags & self.HEADER_CRC_BIT == self.HEADER_CRC_BIT else 1

                            if len(self.packet_bytes) == self.packet_len - crc_len:
                                self.put(self.packet_payload_start, self.samplenum, self.out_ann, [3, ['Payload len %d "%s"' % (len(self.packet_payload_bytes), bytearray(self.packet_payload_bytes).decode("utf-8",'backslashreplace')), '%d' % len(self.packet_payload_bytes)]])
                                self.packet_field = "Maybe CRC"

                        elif self.packet_field == 'Maybe CRC':
                            self.packet_crc = []
                            self.packet_field_start = self.samplenum + 1
                            self.packet_field = "CRC"

                        elif self.packet_field == 'CRC':
                            self.packet_crc.append(self.byte_val)
                            if self.packet_flags & self.HEADER_CRC_BIT == self.HEADER_CRC_BIT:
                                if len(self.packet_crc) == 4:
                                    self.put(self.packet_field_start, self.samplenum, self.out_ann, [3, ['CRC32', 'CRC32']])
                                    self.packet_field = 'Maybe EndPacket'
                            else:
                                self.put(self.packet_field_start, self.samplenum, self.out_ann, [3, ['CRC8', 'CRC8']])
                                self.packet_field = 'Maybe EndPacket'

                        elif self.packet_field == 'Maybe EndPacket':
                            # Need to do this before we exit the loop to read another byte...
                            self.state = "BUSY_TAIL"
                            self.packet_field = "EndPacket" # should never happen.

                        else:
                            self.state = "START_SYNC"
                            self.packet_field = 'UnknownState'


                        if self.packet_field.startswith("Maybe "):
                            keep_parsing = True
                        else:
                            keep_parsing = False


                    self.packet_pos = self.packet_pos+1
                    self.put(self.byte_start, self.samplenum, self.out_ann, [2, ["Byte #%d: 0x%x - %d - '%c'" % (len(self.packet_bytes), self.byte_val, self.byte_val, self.byte_val), '0x%x' % self.byte_val]])

            elif self.state == 'BUSY_TAIL':
                start_busy_tail = self.samplenum


                self.wait([{0: 'r'},{0: 'f'},{'skip': int(self.SWBB_BIT_WIDTH*2)}])


                status = self.wait([{0: 'r'},{0: 'f'},{'skip': int(self.SWBB_BIT_WIDTH*1.1)}])
                last_busy_edge = self.samplenum

                while self.matched[0] or self.matched[1]:
                    last_busy_edge = self.samplenum
                    status = self.wait([{0: 'r'},{0: 'f'},{'skip': int(self.SWBB_BIT_WIDTH*1.1)}])

                #
                # self.put(start_busy_tail, self.samplenum, self.out_ann, [2, ["Hold Busy For Ack", 'BSY']])
                #

                self.put(start_busy_tail, last_busy_edge, self.out_ann, [2, ["Hold Busy for Sync", 'BSY']])

                self.state = 'START_SYNC'
            else:
                continue

