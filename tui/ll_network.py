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
from .packet import packet,_SOCKDOMA,_SOCKTYPE
class int_sock:
    ## Class for handling sockets
    def __init__(self,domain,tx,proto,bk):
        self.domain = domain
        self.type   = tx
        self.proto  = proto
        self.stackt = bk
        self.packets   = []
        #print(self.toPrint())
    ## Helper function to print out the information about the socket
    def toPrint(self):
        ret = []
        ret.append('Socket Information')
        stx = ""
        stx='Socket domain: '+ (_SOCKDOMA[self.domain] if self.domain in _SOCKDOMA else str(self.domain))
        stx+='\nSocket type:'+ (_SOCKTYPE[self.type]   if self.type in _SOCKTYPE else str(self.type))
        stx+='\nSocket protocol:'+str(self.proto)
        ret.append(stx)
        ret.append('Stack calls')
        stx = ""
        for i in self.stackt:
            if i['name'] == None:
                stx+=i['address']
            else:
                stx+=i['address']+' : '+i['name']+'@'+i['moduleName']
                if i['fileName'] != "":
                    stx+='\t->:'+i['linenumber']+'@'+i['fileName']
            stx+='\n'
        ret.append(stx)
        for i in self.packets:
            k = i.toPrint()
            ret = ret + k
        return ret
## Thread. This class is used because it is necessary to retrieve, async, the data from Frida JS
class LL_runner(threading.Thread):
    def __init__(self,ll_data):
        super(LL_runner,self).__init__()
        self.queue   = ll_data.queue
        self.main_frame = ll_data.main_frame
        self.sockets = ll_data.sockets
        self.urw_socks   = ll_data.urw_socks
        self.cont    = ll_data.cont
        self.print_data = ll_data.print_data
    ## Receive data from Frida JS
    def run(self):
        while True:
            item = self.queue.get()
            self.queue.task_done()
            #print(item)
            message=item[0]
            payload=item[1]
            if message['type']=='send':
                msg=message['payload']
                if msg['action'] == 'socket':
                    ## Create a new socket object and add it 
                    s = int_sock(msg['domain'],msg['type'],msg['proto'],msg['bk'])
                    if msg['socket'] not in self.sockets:
                        self.sockets[msg['socket']] = []
                    self.sockets[msg['socket']].append(s)
                    b = urwid.Button((_SOCKDOMA[msg['domain']] if msg['domain'] in _SOCKDOMA else str(msg['domain']))+' : '+str(msg['socket']),on_press = self.print_data, user_data = str(msg['socket'])+'-'+str(len(self.sockets[msg['socket']])-1))
                    self.urw_socks.append(b)
                    continue
                peername = []
                sockname = []
                r_addr = bytes(0x00)
                l_addr = bytes(0x00)
                r_port = bytes(0x00)
                l_port = bytes(0x00)
                sock = msg['socket']    
                

                for i in msg['peername']:
                    peername.append(msg['peername'][i])
                    sockname.append(msg['sockname'][i])
                ## Socket family
                family=struct.unpack('<H',bytes(peername[0:2]))[0]
                if sock not in self.sockets:
                    s = int_sock(family,0,0,msg['bk'])
                    self.sockets[sock] = []
                    self.sockets[sock].append(s)
                    b = urwid.Button((_SOCKDOMA[family] if family in _SOCKDOMA else str(family))+' : '+str(msg['socket']),on_press = self.print_data, user_data = str(msg['socket'])+'-'+str(len(self.sockets[msg['socket']])-1))
                    self.urw_socks.append(b)
                ## TODO: Using SOCKDOMA structure
                ## IPV4 is 2
                if family == 2:
                    r_addr = bytes(peername[4:8])
                    l_addr = bytes(sockname[4:8])
                ## IPV6
                if family == 10:
                    r_addr = bytes(peername[8:24])
                    l_addr = bytes(sockname[8:24])
                ## Port number
                r_port = bytes(peername[2:4])
                l_port = bytes(sockname[2:4])
                
                if msg['action'] == 'send' or msg['action'] == 'sendto':
                    direction = 1
                else:
                    direction = 0
                d = packet(family,r_addr,r_port,l_addr,l_port,payload,direction,msg['action'],msg['bk'])
                self.sockets[sock][-1].packets.append(d)
            elif message['type'] == 'KILL':
                break
            else:
                print(message)
#            
            self.main_frame.loop.draw_screen() 
### TUI main class
class LL_network(urwid.Columns):
    def __init__(self,main_frame):
        ## This is a window && window name
        self.window = True
        self.label = 'Low Level Network Stalker'
        self.main_frame = main_frame
        self.isOver = False
        #self.actionM = ActionMenu(self)
        ## Create new queue
        self.queue = queue.Queue()
        self.main_frame.plugin_queue['LLN'] = self.queue
        ## Data
        self.sockets = {}
        self.urw_socks = urwid.SimpleFocusListWalker([])
        self.sock_list=urwid.LineBox(urwid.ListBox(self.urw_socks))
        self.cont = urwid.SimpleFocusListWalker([])
        self.cc = urwid.ListBox(self.cont);
        super(LL_network,self).__init__([('weight',0.2,self.sock_list),('weight',0.8,self.cc)])
        self.runner = LL_runner(self)
        self.runner.start()
    def print_data(self,button,index):
        ## Delete previous data
        del self.cont[:]
        ## Socket infomation
        inx = index.split('-')
        inx[0] = int(inx[0])
        inx[1] = int(inx[1])
        data   = self.sockets[inx[0]][inx[1]].toPrint()
        ## Header
        i = 0
        while i < len(data): 
            t = urwid.Text(data[i+1])
            self.cont.append(urwid.LineBox(t,title = data[i]))
            i+=2
#    def dumpPcap(self):
#        # Dialog BOX
#        pp = urwid.ProgressBar('','')
#        x = PopUP(self.main_frame,[urwid.Text(u"Exporting the data..."),pp],allow_close = False)
#        self.main_frame.frame.body = x.View()
#        cc = len(self.packets)+2
#        inx = 0
#        ## Creating directory
#        app_name = self.main_frame.frida.app_name
#        b_directory = "./dump/"+app_name+'/network'
#        ## TODO: the filename should be an unique one
#        filename = 'tls_logger.pcap'
#        if not os.path.exists(b_directory):
#            os.makedirs(b_directory)
#        inx += 1
#        pp.set_completion((inx/cc)*100)
#        ## Open the file for writing
#        writef = open(b_directory+'/'+filename,'wb')
#        ## Write the pcap header
#        for writes in (
#            ("=I", 0xa1b2c3d4),     # Magic number
#            ("=H", 2),              # Major version number
#            ("=H", 4),              # Minor version number
#            ("=i", 0),              # GMT to local correction
#            ("=I", 0),              # Accuracy of timestamps
#            ("=I", 65535),          # Max length of captured packets
#            ("=I", 101)):           # Data link type (LINKTYPE_RAW)
#                writef.write(struct.pack(writes[0], writes[1]))
#        inx += 1
#        pp.set_completion((inx/cc)*100)
#        ## For each packet
#        for i in self.packets:
#            if i.direction == 0:
#                src_addr = i.addr_rem
#                dst_addr = i.addr_loc
#                src_port = i.port_rem
#                dst_port = i.port_loc
#            else:
#                src_addr = i.addr_loc
#                dst_addr = i.addr_rem
#                src_port = i.port_loc
#                dst_port = i.port_rem
#            if i.family == 10:
#                ## IPV6
#                header_length = 40
#            elif i.family == 2:
#                ## TODO: IPV4 header
#                header_length = 20
#            for writes in (
#                # PCAP record (packet) header
#                ("=I", int(i.time)),                        # Timestamp seconds
#                ("=I", int((i.time * 1000000) % 1000000)),  # Timestamp microseconds
#                ("=I", header_length + 20 + len(i.data)),   # Number of octets saved
#                ("=I", header_length + 20 + len(i.data))    # Actual length of packet
#                ):
#                    writef.write(struct.pack(writes[0],writes[1]))
#            if i.family == 10:
#                for writes in (
#                    # IPv6 header
#                    (">I", 0x60000000),                      # Version, Traffic class and Flow Label
#                    (">H", 20+len(i.data)),              # Payload length
#                    (">B", 6),                           # Next Header
#                    (">B", 0xFF),                        # TTL Like
#                    ):
#                        writef.write(struct.pack(writes[0],writes[1]))
#                writef.write(src_addr)
#                writef.write(dst_addr)
#            # TCP header
#            writef.write(src_port)
#            writef.write(dst_port)
#            for writes in (
#                (">I", 0),                        # Sequence Number
#                (">I", 0),                        # Acknowledgment Number
#                (">H", 0x5018),                   # Header Length and Flags
#                (">H", 0xFFFF),                   # Window Size
#                (">H", 0),                        # Checksum
#                (">H", 0)
#                ):                       # Urgent Pointer
#                    writef.write(struct.pack(writes[0], writes[1]))
#            writef.write(i.data)
#            inx+=1
#            pp.set_completion((inx/cc)*100)
#        writef.close()
#        x = PopUP(self.main_frame,[urwid.Text(u"Export complete!"),pp])
#        self.main_frame.frame.body = x.View()
#    def keypress(self,size,key):
#        if key in ('c','C'):
#        ##Clear the current history
#            del self.data[:]
#            self.info.set_text(u"")
#            self.payload.set_text(u"")
#        if key in ('e','E'):
#            self.dumpPcap()
#        if key == 'a':
#            self.main_frame.frame.body = self.actionM.View()
#        else:
#            return super(TLS_connection,self).keypress(size,key)   
#
#class ActionMenu(PopUP):
#    def __init__(self,packets):
#        text = ["Export all the packets (pcap format) (<e>)"]
#        self.pack = packets
#        opt = []
#        for i in text:
#            opt.append(urwid.Button(i,on_press = self.Action,user_data = i.split('<')[1].split('>')[0]))
#        super(ActionMenu,self).__init__(packets.main_frame,opt,'Action menu')
#    def Action(self,key,name):
#        if name == 'e':
#            self.pack.dumpPcap()
#            super(ActionMenu,self).keypress(None,'esc')
