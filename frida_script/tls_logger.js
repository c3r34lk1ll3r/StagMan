/*************************************************
** This script allows to log TLS read/write. It  *
** is usefull for intercept the data trasmitted  *
** in an encrypted channel.the file created      *
** NOTE: If an application does not use TLS or   *
** it uses a different library, this script will *
** not capture any data. (E.g. Flutter use a     * 
** different TLS library called 'BoringTLS' or   *
** something like that                           *
**************************************************/

//Resolve address for dynamic hooking
function Resolv_Address() {
   var addrs = {};
   var platform = Process.platform;
   if (platform == 'linux') {
    addrs["SSL_read"] = Module.getExportByName('libssl.so','SSL_read'); 
    addrs["SSL_write"] = Module.getExportByName('libssl.so','SSL_write'); 
    addrs["SSL_get_fd"] = Module.getExportByName('libssl.so','SSL_get_fd'); 
    try {
        addrs["getpeername"] = Module.getExportByName('libc.so','getpeername'); 
        addrs["getsockname"] = Module.getExportByName('libc.so','getsockname');
    } catch(err) {
        addrs["getpeername"] = Module.getExportByName('libc.so.6','getpeername'); 
        addrs["getsockname"] = Module.getExportByName('libc.so.6','getsockname');
    }
    addrs["SSL_SESSION_get_id"] = Module.getExportByName('libssl.so','SSL_SESSION_get_id');
    addrs["SSL_get_session"] = Module.getExportByName('libssl.so','SSL_get_session');
   }
   var funct = {};
   funct['SSL_get_fd']          = new NativeFunction(addrs["SSL_get_fd"],"int",["pointer"]);
   funct['SSL_SESSION_get_id']  = new NativeFunction(addrs["SSL_SESSION_get_id"],"pointer",['pointer','pointer']);
   funct['SSL_get_session']     = new NativeFunction(addrs["SSL_get_session"],"pointer",['pointer']);
   funct['getpeername']         = new NativeFunction(addrs["getpeername"],"int",["int","pointer","pointer"]);
   funct['getsockname']         = new NativeFunction(addrs["getsockname"], "int", ["int","pointer","pointer"]);
   funct['SSL_read']            = addrs['SSL_read'];
   funct["SSL_write"]           = addrs['SSL_write']; 
  
   //Debugging purpose
   //console.log('Functions address:');
   //console.log('\tSSL_read:'+      addrs["SSL_read"]);
   //console.log('\tSSL_write:'+     addrs["SSL_write"]);
   //console.log('\tSSL_get_fd:'+    addrs["SSL_get_fd"]);
   //console.log('\tgetpeername:'+   addrs["getpeername"]);
   //console.log('\tgetsockname:'+   addrs["getsockname"]);
   //console.log('\tgetfd:'+         addrs["SSL_get_fd"]);
   //console.log('\tntohs:'+         addrs["ntohs"]);
   //console.log('\tinet_ntop:'+     addrs["inet_ntop"]);
   //console.log('\n\n\n');
   return funct;
}

function SSL_Handler_data(data) {
   //Retrieve SSL Session
   /*
   var session = funct['SSL_get_session'](data.ssl);
   //Retrieve SSL_Session ID
   var len = Memory.alloc(4);
   var id = funct['SSL_SESSION_get_id'](session,len);
   len = len.readU32();
   var i;
   data.obj['session_id'] = "";
   //console.log('length:'+len);
   for(i=0;i<len;i++) { 
    var l = id.readU8().toString(16);
    data.obj['session_id'] = data.obj['session_id'].concat(l);
    id=id.add(1)
   }
   console.log(data.obj['session_id'])
   */
   //Allocate the data for the next getpeername call
   var sockaddr = Memory.alloc(28);
   var addrlen = Memory.alloc(4);
   //I will write the address len at 28 bytes in order to obtain IPv6 otherwise therespons will be truncated.
   addrlen.writeUInt(28);
   //Retrieve the FD of the socket
   var fd=funct['SSL_get_fd'](data.ssl);
   data.obj['fd'] = fd
   if ( funct['getpeername'](fd,sockaddr,addrlen) == 0) {
      //Read the sockaddr structure
      var header = Memory.readByteArray(sockaddr,28)
      data.obj['peername']=new Uint8Array(header,0,28)
   }
   //Same thing for the local socket
   addrlen.writeUInt(28);
   if ( funct['getsockname'](fd,sockaddr,addrlen) == 0) {
      var header = Memory.readByteArray(sockaddr,28)
      data.obj['sockname'] = new Uint8Array(header,0,28)
   }
   var p=ptr(data.buffer);
   var array=Memory.readByteArray(p,data.obj['numret']);
   //console.log(hexdump(array))
   send(data.obj,array);
}

var funct=Resolv_Address();


Interceptor.attach(funct["SSL_read"],
{
   //I only need to store the data
   onEnter: function (args) {
      this.ssl=args[0];
      this.buffer=args[1];
      this.num=args[2];
      this.obj = {};
      this.obj['bk'] = Thread.backtrace(this.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress);
   },
   //When the function will return, I have access to the data
   onLeave: function (retval) {
      //# Bytes readed
      var ret = retval.toInt32();
      this.obj['plugin']='TLSP';
      this.obj['numret']=ret;
      //If the # of bytes are <=0 --> ERROR
      if (ret <= 0) {
         this.obj['action'] = 'ERR';
         send(this.obj);
      }
      else {
         this.obj['action']= 'SSL_read';
         SSL_Handler_data(this);
         //send(this.obj);
      }         
   }
});

Interceptor.attach(funct["SSL_write"],
{
   onEnter: function (args) {
      this.ssl=args[0];
      this.buffer=args[1];
      this.num=args[2];
      this.obj = {};
      this.obj['bk'] = Thread.backtrace(this.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress);
   },
   onLeave: function (retval) {
      var ret = retval.toInt32();
      this.obj['plugin']='TLSP';
      this.obj['numret']=ret;
      if (ret <= 0) {
         this.obj['action'] = 'ERR';
      }
      else {
         this.obj['action']= 'SSL_write';
         SSL_Handler_data(this);
      }         
   }
});
