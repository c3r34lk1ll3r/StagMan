#-*- encoding: utf-8 -*-

import urwid
import threading
import queue
import subprocess
import gzip
import time
import os
import struct
import socket
from .pop_up import PopUP
from .packet import packet
class int_tls:
    def __init__(self,head):
        self.r_addr = head[0];
        self.r_port = head[1];
        self.l_addr = head[2];
        self.l_port = head[3];
        self.packets = []
    def toPrint(self):
        ret = []
        for i in self.packets:
            ret = ret+i.toPrint()
        return ret
    def toRawData(self):
        data = b""
        for i in self.packets:
            data+=i.data
            data+=b"\n\n"
        return data
    def toPcapData(self):
        ret = b""
        send = 0
        recv = 0
        for i in self.packets:
            #PCAP record (packet) header
            ## Header is only for ipv6
            header_length = 40
            ret += struct.pack("=I", int(i.time))                       #Timestamp in seconds
            ret += struct.pack("=I", int(i.time*1000000) % 1000000)     #Timestamp in microseconds
            ret += struct.pack("=I", header_length + 20 + len(i.data))  # Number of octets saved
            ret += struct.pack("=I", header_length + 20 + len(i.data))  # Actual length of packet
            ## IPV6 Header
            if i.direction == 0:
                src_addr = i.addr_rem
                dst_addr = i.addr_loc
                src_port = i.port_rem
                dst_port = i.port_loc
            else:
                src_addr = i.addr_loc
                dst_addr = i.addr_rem
                src_port = i.port_rem
                dst_port = i.port_loc
            ret += struct.pack(">I", 0x60000000)                        # Version, traffic class and flow label
            ret += struct.pack(">H", 20 + len(i.data))                  # Payload length
            ret += struct.pack(">B", 6)                                 # Next header
            ret += struct.pack(">B", 0xFF)                              # TTL Like
            ret += src_addr
            ret += dst_addr
            ## TCP Header
            ret += src_port
            ret += dst_port
            ret += struct.pack(">I", send)                              # Sequence number
            ret += struct.pack(">I", recv)                              # ACK Number
            ret += struct.pack(">H", 0x5018)                            # Header length and flags
            ret += struct.pack(">H", 0xFFFF)                            # Window size
            ret += struct.pack(">H", 0x0)                               # Checksum
            ret += struct.pack(">H", 0x0)                               # Urgent Pointer
            ret += i.data
            if i.direction == 0:
                recv += len(i.data)
            else:
                send += len(i.data)
        return ret

## Thread. This class is used because it is necessary to retrieve, async, the data from Frida JS
class TLS_runner(threading.Thread):
    def __init__(self,tls_conn):
        super(TLS_runner,self).__init__()
        ## The frida event queue
        self.queue = tls_conn.queue
        ## The FD structure
        self.connections = tls_conn.connections
        self.urw_conn = tls_conn.urw_conn
        #self.packets = tls_conn.packets
        #self.data = tls_conn.data
        self.print_data = tls_conn.print_data
        self.main_frame = tls_conn.main_frame
        #self.test = tls_conn.dumpPcap
    
    ## Receive data from Frida JS
    def run(self):
        while True:
            item = self.queue.get()
            ## Clear the queue
            self.queue.task_done()
            ## Split the message
            #print(item)
            message=item[0]
            payload=item[1]
            if message['type']=='send':
                msg=message['payload']
                if msg['action'] == 'ERR':
                    continue
                ## Parsing header
                peername = []
                sockname = []
                for i in msg['peername']:
                    peername.append(msg['peername'][i])
                    sockname.append(msg['sockname'][i])
                ## Socket family
                family=struct.unpack('<H',bytes(peername[0:2]))[0]
                ## TODO: Import from packets
                ## IPV4 is 2
                ## IPV6
                if family == 10:
                    r_addr = bytes(peername[8:24])
                    l_addr = bytes(sockname[8:24])
                ## Port number
                r_port = bytes(peername[2:4])
                l_port = bytes(sockname[2:4])
                if msg['action'] == 'SSL_read':
                    # IN
                    direction = 0
                elif msg['action'] == 'SSL_write':
                    #OUT
                    direction = 1
                d = packet(family, r_addr, r_port, l_addr, l_port, payload, direction,msg['action'],msg['bk'])
                if msg['fd'] not in self.connections:
                    self.connections[msg['fd']] = []
                    s = int_tls([r_addr,r_port,l_addr,l_port])
                    s.packets.append(d)
                    self.connections[msg['fd']].append(s)
                    b = urwid.Button(d.view)
                    b.hidden_name = str(msg['fd']) + '-'+str(len(self.connections[msg['fd']])-1)
                    urwid.connect_signal(b,'click',self.print_data,b.hidden_name)
                    self.urw_conn.append(b)
                    continue
                ## Check if this is a new connection or a previous one
                i = self.connections[msg['fd']][-1]
                if (i.r_addr == r_addr) and (i.r_port == r_port) and (i.l_addr == i.l_addr) and (i.l_port == l_port):
                    ## Append packet
                    if i.packets[-1].action == d.action:
                        i.packets[-1].data += d.data
                    else:
                        i.packets.append(d)
                else:
                    s = int_tls([r_addr,r_port,l_addr,l_port])
                    s.packets.append(d)
                    self.connections[msg['fd']].append(s)
                    b = urwid.Button(d.view)
                    b.hidden_name = str(msg['fd']) + '-'+str(len(self.connections[msg['fd']])-1)
                    urwid.connect_signal(b,'click',self.print_data,str(msg['fd'])+'-'+str(len(self.connections[msg['fd']])-1))
                    self.urw_conn.append(b)
            elif message['type'] == 'KILL':
                break
            else:
                print(message)
            self.main_frame.loop.draw_screen() 
## TUI main class
class TLS_connection(urwid.Columns):
    def __init__(self,main_frame):
        ## This is a window && window name
        self.window                          = True
        self.label                           = 'TLS Logger'
        self.main_frame                      = main_frame
        self.isOver                          = False
        self.actionM                         = ActionMenu(self)
        ## Create new queue
        self.queue                           = queue.Queue()
        self.main_frame.plugin_queue['TLSP'] = self.queue
        self.connections                     = {}
        self.urw_conn                        = urwid.SimpleFocusListWalker([])
        self.listBox_conn                    = urwid.ListBox(self.urw_conn)
        connection_status                    = urwid.LineBox(self.listBox_conn)
        self.cont = urwid.SimpleFocusListWalker([])
        self.cc = urwid.ListBox(self.cont)
        super(TLS_connection,self).__init__([('weight',0.2,connection_status),('weight',0.8,self.cc)])
        self.runner = TLS_runner(self)
        self.runner.start()
    def print_data(self,button,index):
        del self.cont[:]
        ## Socket information
        inx = index.split('-')
        inx[0] = int(inx[0])
        inx[1] = int(inx[1])
        data = self.connections[inx[0]][inx[1]].toPrint()
        i = 0
        while i < len(data):
            t = urwid.Text(data[i+1])
            self.cont.append(urwid.LineBox(t,title = data[i]))
            i+=2
    ## TODO: Fix the new structure
    def dumpPcap(self):
        # Dialog BOX
        pp = urwid.ProgressBar('','')
        x = PopUP(self.main_frame,[urwid.Text(u"Exporting the data..."),pp],allow_close = False)
        self.main_frame.frame.body = x.View()
        cc = len(self.connections)+2
        inx = 0
        ## Creating directory
        app_name = self.main_frame.frida.app_name
        b_directory = "./dump/"+app_name+'/network'
        ## TODO: the filename should be an unique one
        filename = 'tls_logger.pcap'
        if not os.path.exists(b_directory):
            os.makedirs(b_directory)
        inx += 1
        pp.set_completion((inx/cc)*100)
        ## Open the file for writing
        writef = open(b_directory+'/'+filename,'wb')
        ## Write the pcap header
        for writes in (
            ("=I", 0xa1b2c3d4),     # Magic number
            ("=H", 2),              # Major version number
            ("=H", 4),              # Minor version number
            ("=i", 0),              # GMT to local correction
            ("=I", 0),              # Accuracy of timestamps
            ("=I", 65535),          # Max length of captured packets
            ("=I", 101)):           # Data link type (LINKTYPE_RAW)
                writef.write(struct.pack(writes[0], writes[1]))
        inx += 1
        pp.set_completion((inx/cc)*100)
        ## For each connections
        for i in self.connections:
            for j in self.connections[i]:
                writef.write(j.toPcapData())
                pp.set_completion((inx/cc)*100)
        #for i in self.connections:
        #    send = 0
        #    recv = 0
        #    for k in self.connections[i]:
        #        for j in k.packets:
                #    inx+=1

        writef.close()
        x = PopUP(self.main_frame,[urwid.Text(u"Export complete!"),pp])
        self.main_frame.frame.body = x.View()
    def dumpPacket(self):
        position = self.urw_conn.positions()
        focus = self.urw_conn.focus
        b = self.urw_conn[focus]
        index = b.hidden_name
        inx = index.split('-')
        inx[0] = int(inx[0])
        inx[1] = int(inx[1])
        app_name = self.main_frame.frida.app_name
        b_directory = "./dump/"+app_name+'/network'
        ## TODO: the filename should be an unique one
        if not os.path.exists(b_directory):
            os.makedirs(b_directory)
        data = self.connections[inx[0]][inx[1]].toRawData()
        i = 0
        writef = open(b_directory+'/'+b.get_label()+index,'wb')
        writef.write(data)
        writef.close()
    def keypress(self,size,key):
        if key in ('c','C'):
        ##Clear the current history
            self.connections.clear()
            del self.urw_conn[:]
        if key == 'E':
            self.dumpPcap()
        if key == 'e':
            self.dumpPacket()
        if key == 'a':
            self.main_frame.frame.body = self.actionM.View()
        else:
            return super(TLS_connection,self).keypress(size,key)   

class ActionMenu(PopUP):
    def __init__(self,packets):
        text = ["Export the selected packet (<e>)","Export all the packets (pcap format) (<E>)"]
        self.pack = packets
        opt = []
        for i in text:
            opt.append(urwid.Button(i,on_press = self.Action,user_data = i.split('<')[1].split('>')[0]))
        super(ActionMenu,self).__init__(packets.main_frame,opt,'Action menu')
    def Action(self,key,name):
        if name == 'E':
            self.pack.dumpPcap()
            super(ActionMenu,self).keypress(None,'esc')
        if name == 'e':
            self.pack.dumpPacket()
            super(ActionMenu,self).keypress(None,'esc')
