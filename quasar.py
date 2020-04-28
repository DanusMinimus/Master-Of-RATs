import os
import base64
import gzip
import io
import random
import string
import sys
from OpenSSL import SSL

import stage_props.winapi as winapi
import stage_props.network as network
import stage_props.process_manager as process_manager
import stage_props.utils as utils
import stage_props.filesystem as filesystem

import plugins.clientidentity as client

from datetime import datetime
from enum import Enum

from plugins.puppet_rat import PuppetRAT

"""
Protobuf varint function encoder
"""
def encode_varint(value):

    varint_list = bytearray([0x0a])

    if value < 0:
        value += (1 << 64)
    bits = value & 0x7f
    value >>= 7

    while value:
        varint_list.append(0x80 | bits)
        bits = value & 0x7f
        value >>= 7

    varint_list.append(bits)
    return varint_list

"""
Returns the size of a self.messagesage in little endian format
"""
def len_to_byte(value):
    return value.to_bytes(4,  byteorder='little')

"""
Quasar constructor, please set the Tag, ID, Encryption Key and Signature values yourself
"""
class Quasar(PuppetRAT):

    def __init__(self, client_ip: str, client_port: int) -> None:
        super(Quasar, self).__init__(client_ip, client_port)
        self.Version = "1.3.0.0"
        self.Username = winapi.get_user_name()
        self.Tag = None
        self.Region = "UNK"
        self.PcName = "User"
        self.OperatingSystem = "Windows 7 64 bits Home Edition"
        self.ImageIndex = 103
        self.Id = None
        self.EncryptionKey = None
        self.CountryCode = "UNK"
        self.Country = "UNKNOWN"
        self.City = "UNK"
        self.AccountType = "Admin"
        self.Signature = None
        self.message = client.ClientIdentification()
        
        self.ctx = None
        self.logged_in_user = winapi.get_user_name()
        self.volume_serial = winapi.get_volume_serial_number()
        vfs_root = os.path.join(os.path.dirname(__file__), '..', 'artifacts', f'{client_ip}_{client_port}')
        self.vfs = filesystem.VirtualFileSystem(vfs_root, self.logged_in_user)
        self.screenshot = None

    def set_tag(self, tag: str):
        self.Tag = tag

    def set_id(self, id: str):
        self.Id = id

    def set_key(self, key: str):
        self.EncryptionKey = key

    def set_sig(self, sig: bytearray):
        self.Signature = sig

    def build_message(self):
        self.message.Version = self.Version
        self.message.Username = self.Username
        self.message.Tag = self.Tag
        self.message.Region = self.Region
        self.message.PcName = self.PcName
        self.message.OperatingSystem = self.OperatingSystem
        self.message.ImageIndex = self.ImageIndex
        self.message.Id = self.Id
        self.message.EncryptionKey = self.EncryptionKey
        self.message.CountryCode = self.CountryCode
        self.message.Country = self.Country
        self.message.City = self.City
        self.message.AccountType = self.AccountType
        self.message.Signature = self.Signature

    def __del__(self):
        self.conn.close()

    def connect(self):
        self.logger.debug(f'[*]Connecting to Quasar client')
        self.conn = utils.tcp_socket()
        self.ctx, self.conn = utils.create_ssl_sock(self.conn)
        try:
            self.conn.connect((self.client_ip, self.client_port))
            self.conn.do_handshake()
            self.logger.debug(f'[*]Connected to server and performed handshake!')
        except:
            self.logger.debug(f'[*]Failed to connect!')
            self.conn.close()
            sys.exit(1)

    def send(self, msg: str):
        write(msg)

    def recv(self):
        raw = self.conn.recv(1024)
        return raw

    def loop(self):
        while True:
            msg = self.recv()
            self.logger.debug(f'[*] received msg "{msg}"')
            if not len(msg):
                self._ping()
            else:
                print(f'[*] received msg "{msg}"')
                self.logger.debug(f'[*] received msg "{msg}"')


    def register(self):
        """https://github.com/mwsrc/njRAT/blob/539aa13375473d9c9bf74e81e65bb34bdb348a30/njRAT/Stub/OK.VB#L993"""
        self.logger.debug(f'[*] Registrating fake Quasar client!')
        self._register()
        self.build_message()

        # self.messagesage size https://stackoverflow.com/questions/61412249/protobuf-net-unrecognized-stream-prefix?noredirect=1#comment108646492_61412249
        message_string = self.message.SerializeToString()
        message_len_encoded = encode_varint(len(message_string))

        message_string = message_len_encoded + message_string

        message_len_real = len_to_byte(len(message_string))
        message_string = message_len_real + message_string
        self.conn.write(message_string)

    def _register(self):
        self.set_tag("Puppet")
        self.set_id("A8AE9A15885A8B8CE8CAC3015772BB961C182EE7491EAEE4C7478E25DB10B9BE")
        self.set_key("NprYl9CF1DrvD0aSBuNCPYpHqNw3nh03")
        self.set_sig(b'\x44\x5B\x23\xAA\x2C\x0D\xEA\x17\x2B\x1D\x38\x23\x7F\x33\xCB\xFE' + \
                    b'\x2D\xAB\x6B\xE2\x26\x69\x40\x8B\x7F\xED\x6E\x45\xA5\x3B\xF7\x58' + \
                    b'\x1D\x1A\x07\xB3\xA0\x99\xCD\x67\x2A\xBC\xE5\x41\xB3\x8D\xB1\xE1' + \
                    b'\xDB\x4E\x30\x09\xC4\xFC\x0A\x25\x5B\xB4\x82\xC8\x40\xA0\x0F\x1F' + \
                    b'\xA7\x16\xD6\x47\xC1\x06\xD5\xD8\xE1\xDA\xAD\xDD\x56\xAD\x2F\xE2' + \
                    b'\xF0\xF4\x89\x72\xC8\x2C\x42\xC2\xBC\x45\x8C\xBE\xCE\x72\x4A\x76' + \
                    b'\x20\xCD\x12\xB8\x66\x08\xAF\xD7\xA4\xF4\x28\x66\xC9\x33\x5B\xB8' + \
                    b'\x5E\x83\x9A\x8C\xD2\xDB\x59\xF5\x43\x7E\xE3\x0D\xA5\xA7\xC3\x66' + \
                    b'\x45\xB8\x5B\xC0\xD9\x8A\x30\x4E\x68\x9C\x66\xD5\x1D\x2E\x5F\xDC' + \
                    b'\xC3\xE2\x57\x86\xA2\x61\xC2\x93\xC2\x2D\x43\xA2\x31\xDA\x68\xD0' + \
                    b'\xF0\x3B\x43\x31\x0D\xAD\x38\x97\x7E\x45\x6F\x68\x60\xF9\x9F\x47' + \
                    b'\xF1\x01\x3E\x4A\x71\x8C\x9A\xB6\xFC\x5E\x5E\xDB\x0C\xF5\x95\xE1' + \
                    b'\xA0\x90\xDB\x06\xBB\xAE\x63\xAD\x43\xB2\xAC\x2E\xB7\x67\x4C\x13' + \
                    b'\x3C\x97\xA6\x22\x87\x19\x10\x3F\xC1\xAF\xD0\x9A\xC6\x23\x90\x55' + \
                    b'\x5D\x24\xDF\x27\x0E\x13\x6E\xFF\x91\x01\x8D\xD6\xDB\x02\x16\xBD' + \
                    b'\x3E\xAE\xDF\xA2\xC0\xD6\x85\x48\x21\xD0\x6D\xB0\x1C\x2E\xC1\x4A' + \
                    b'\x36\xCB\x88\x00\x84\xC9\x64\xA0\x01\xC3\xA8\x3C\x22\xE0\xAC\x62' + \
                    b'\xDD\x6B\x03\x56\xEE\x11\x25\xF5\x2B\x31\x8A\x95\xBE\x44\xFF\xB3' + \
                    b'\xDF\x0B\xDE\xF0\x36\xA5\x0A\xB0\xBF\x62\x4D\x81\xB3\xA2\xBB\x05' + \
                    b'\x38\x45\x79\x08\x29\x71\x43\x2E\xAC\xF9\x45\x29\xB6\x23\x32\xD1' + \
                    b'\x5A\x4A\xBC\xFB\x56\xF4\x09\xDB\x70\xDF\xC5\x1B\x5F\x02\x5C\x33' + \
                    b'\x45\x9C\x86\x2F\x00\xF6\xA2\x15\xC2\xC1\x25\xA1\x27\x71\x79\x2A' + \
                    b'\x46\x70\xEA\x9B\xF3\x43\x7D\x3D\x85\x11\xAC\xF1\xBA\x90\x07\xFC' + \
                    b'\x18\x68\x76\x4E\x19\xF5\xFB\x7D\xFA\x1D\x4D\x90\x6C\x70\x03\x22' + \
                    b'\x3A\xB0\xB7\x9F\xA0\x10\xA5\x62\x07\x7B\x6D\x12\xC0\x38\xFF\xF0' + \
                    b'\x8D\xE9\x57\x58\xD2\x95\xF7\xCC\x00\x16\xA2\x0E\x42\x40\xEA\xC8' + \
                    b'\xE6\x53\x89\x6B\xEB\xB9\xF8\xF2\x1D\x69\x9E\x6B\xF6\xD5\x05\x5F' + \
                    b'\x0B\xA9\xC4\x5D\x34\x7C\x3E\x6C\x09\xF7\xB3\xFC\x15\xEC\x5E\x7A' + \
                    b'\xE0\xD3\x7B\x30\xF2\xD9\xEE\x7C\x9C\x4E\x50\x1B\xA0\xD1\xF0\x94' + \
                    b'\x57\x09\xC0\xB2\x74\x13\x9A\x0C\x29\x72\x8E\xE3\x5E\x9A\x2E\x09' + \
                    b'\x5C\x20\x9C\x04\x13\x2D\x88\x72\x37\xDF\x62\xC0\xE9\x84\x46\x0A' + \
                    b'\xA4\x21\x98\x11\x96\xB9\x7A\x71\x20\xE8\x02\xBE\xA0\x82\x03\x2D')

    """    
    @property
    def victim_id(self) -> str:
        return base64.b64encode('HacKed_{:08X}'.format(self.volume_serial).encode()).decode()
    

    def _send_screenshot(self, width, height):
        if not self.screenshot:
            self.screenshot = winapi.capture_screen(min(int(width), 512),
                                                                min(int(height), 512))
        self.send_bytes(b'CAP|\'|\'|' + self.screenshot)
    """

    def _ping(self):
        self.send('')
