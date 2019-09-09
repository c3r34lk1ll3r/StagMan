import time
import socket
import struct
import subprocess
import gzip
_SOCKDOMA     = {}
_SOCKDOMA[0]  = 'AF_UNSPEC'
_SOCKDOMA[1]  = 'AF_UNIX'
_SOCKDOMA[2]  = 'AF_INET' 
_SOCKDOMA[3]  = 'AF_AX25'
_SOCKDOMA[4]  = 'AF_IPX'
_SOCKDOMA[5]  = 'AF_APPLETALK' 
_SOCKDOMA[6]  = 'AF_NETROM'
_SOCKDOMA[7]  = 'AF_BRIDGE'
_SOCKDOMA[8]  = 'AF_ATMPVC'
_SOCKDOMA[9]  = 'AF_X25'
_SOCKDOMA[10] = 'AF_INET6' 
_SOCKDOMA[11] = 'AF_ROSE'
_SOCKDOMA[12] = 'AF_DECnet' 
_SOCKDOMA[13] = 'AF_NETBEUI' 
_SOCKDOMA[14] = 'AF_SECURITY' 
_SOCKDOMA[15] = 'AF_KEY'
_SOCKDOMA[16] = 'AF_NETLINK'
_SOCKDOMA[17] = 'AF_PACKET'
_SOCKDOMA[18] = 'AF_ASH'
_SOCKDOMA[19] = 'AF_ECONET' 
_SOCKDOMA[20] = 'AF_ATMSVC'
_SOCKDOMA[21] = 'AF_RDS'
_SOCKDOMA[22] = 'AF_SNA'
_SOCKDOMA[23] = 'AF_IRDA'
_SOCKDOMA[24] = 'AF_PPPOX'
_SOCKDOMA[25] = 'AF_WANPIPE' 
_SOCKDOMA[26] = 'AF_LLC'
_SOCKDOMA[29] = 'AF_CAN'
_SOCKDOMA[30] = 'AF_TIPC'
_SOCKDOMA[31] = 'AF_BLUETOOTH' 
_SOCKDOMA[32] = 'AF_IUCV'
_SOCKDOMA[33] = 'AF_RXRPC' 
_SOCKDOMA[34] = 'AF_ISDN' 
_SOCKDOMA[35] = 'AF_PHONET' 
_SOCKDOMA[36] = 'AF_IEEE802154' 
_SOCKDOMA[37] = 'AF_CAIF'
_SOCKDOMA[38] = 'AF_ALG' 
_SOCKDOMA[39] = 'AF_NFC' 
_SOCKDOMA[40] = 'AF_VSOCK' 
_SOCKDOMA[41] = 'AF_KCM' 
_SOCKDOMA[42] = 'AF_QIPCRTR' 
_SOCKDOMA[43] = 'AF_MAX' 
_SOCKTYPE     = {}
_SOCKTYPE[1]  = 'SOCK_STREAM'
_SOCKTYPE[2]  = 'SOCK_DGRAM' 
_SOCKTYPE[3]  = 'SOCK_RAW'    
_SOCKTYPE[4]  = 'SOCK_RDM'      
_SOCKTYPE[5]  = 'SOCK_SEQPACKET'  
_SOCKTYPE[6]  = 'SOCK_DCCP'      
_SOCKTYPE[10] = 'SOCK_PACKET'      
class packet:
    ## Class for handling packets
    def __init__(self,family,addr_rem,port_rem,addr_loc,port_loc,data,direction,action,bk):
        self.family = family
        self.time = time.time()
        self.stackt = bk
        ## Remote address && port
        self.addr_rem=addr_rem
        self.port_rem=port_rem
        ## Local address && port
        self.addr_loc=addr_loc
        self.port_loc=port_loc
        ## pkt content
        self.data=data
        ## Received or sended
        self.direction=direction
        ## Hooked function
        self.action = action
        ## To allow a reverse-dns view of the remote host
        ## Convert remote address to string
        if _SOCKDOMA[self.family] == 'AF_INET' or _SOCKDOMA[self.family] == 'AF_INET6':
            self.view = socket.inet_ntop(self.family,addr_rem)
            if '.' in self.view:
                self.view = self.view.split(':')[-1]
        ## DNS IS STRANGE
            self.dns_resolv=subprocess.check_output(["dig", "-x", self.view,"+short"]).decode('utf-8')
            if self.dns_resolv.strip() != u"":
               self.view = str(self.dns_resolv.strip())
    
    ## Helper function to print out the information about the packet
    def toPrint(self):
        ret = []
        ret.append(self.action)
        stx ='Packet family:'+(_SOCKDOMA[self.family] if self.family in _SOCKDOMA else str(self.family))
        if _SOCKDOMA[self.family] == 'AF_INET' or _SOCKDOMA[self.family] == 'AF_INET6':
            stx+='\nLocal address:'+socket.inet_ntop(self.family,self.addr_loc)+':'+str(struct.unpack('!H',self.port_loc)[0])
            stx+='\nRemote address:'+self.view+':'+str(struct.unpack('!H',self.port_rem)[0])
        else:
            stx+='\nLocal address:'+str(self.addr_loc)
            stx+='\nRemote address:'+str(self.addr_rem)
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
        ret.append('Packet content')
        cont = str(self.data)
        ## Handling HTTP data
        if b'HTTP' in self.data:
            div = self.data.partition(b'\r\n\r\n')
            header = str(div[0]).replace('\\r','').replace('\\n','\n')[2:-1]
            body = div[-1]
            try:
                if u'Content-Encoding' in header:
                    if u'gzip' in header or u'GZIP' in header:
                        body = gzip.decompress(body)
                    if 'utf-8' in header or 'UTF-8' in header:
                        body = body.decode('utf-8','backslaskreplace')
                else:
                    body = str(body).replace('\\r','\r').replace('\\n','\n')[2:-1]
                cont = header +'\n\n' + body
            except Exception:
                cont = str('Decoding Error. Raw bytes:\n\n')+str(self.data)
        ret.append(cont)
        return ret
