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
   addrs["getsockname"] = Module.getExportByName('libc.so','getsockname');
   addrs["getpeername"] = Module.getExportByName('libc.so','getpeername');
   var funct = {};
   funct["socket"]      = Module.getExportByName('libc.so','socket');
   funct["send"]        = Module.getExportByName('libc.so','send'); 
   funct["sendto"]      = Module.getExportByName('libc.so','sendto'); 
   funct["recv"]        = Module.getExportByName('libc.so','recv'); 
   funct["recvfrom"]    = Module.getExportByName('libc.so','recvfrom'); 
   funct['sendmsg']     = Module.getExportByName('libc.so','sendmsg');
   funct['recvmsg']     = Module.getExportByName('libc.so','recvmsg');
   funct['getpeername'] = new NativeFunction(addrs["getpeername"],"int",["int","pointer","pointer"]);
   funct['getsockname'] = new NativeFunction(addrs["getsockname"], "int", ["int","pointer","pointer"]);
   return funct;
}

function Handler_Data(data){
   var sockaddr = Memory.alloc(28);
   var addrlen = Memory.alloc(4);
   //I will write the address len at 28 bytes in order to obtain IPv6 otherwise therespons will be truncated.
   addrlen.writeUInt(28);
   if (funct['getpeername'](data.obj['socket'],sockaddr,addrlen) == 0) {
      //Read the sockaddr structure
      var header = Memory.readByteArray(sockaddr,28)
      data.obj['peername'] = new Uint8Array(header,0,28)
   }
   //Same thing for the local socket
   addrlen.writeUInt(28);
   if ( funct['getsockname'](data.obj['socket'],sockaddr,addrlen) == 0) {
      //Read the sockaddr structure
      var header = Memory.readByteArray(sockaddr,28)
      data.obj['sockname'] = new Uint8Array(header,0,28);
   }
   var p=ptr(data.buffer);
   var array=Memory.readByteArray(p,data.obj['numret']);
   send(data.obj,array);
   //console.log('-------- '+data.obj['action']+ ' --------------')
   //console.log('Socket: '+data.obj['socket']);
   //console.log('Header peer dump:\n'+data.obj['peername']);
   //console.log('Header sock dump:\n'+data.obj['sockname']);
   //console.log('Data peer dump:\n'+hexdump(array,{length:data.obj['numret']}));
}

var funct=Resolv_Address();
Interceptor.attach(funct["socket"],
{
   onEnter: function (args) {
        this.obj           = {}
        this.obj['plugin'] = 'LLN';
        this.obj['action'] = 'socket';
        this.obj['domain'] = args[0].toInt32();
        this.obj['type']   = args[1].toInt32();
        this.obj['proto']  = args[2].toInt32();
        this.obj['bk']     = Thread.backtrace(this.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress);
   },
   onLeave: function (retval) {
        this.obj['socket'] = retval.toInt32();
        send(this.obj,null);
   }
});
Interceptor.attach(funct["send"],
{
   onEnter: function (args) {
        this.obj           = {};
        this.obj['plugin'] = 'LLN';
        this.obj['action'] = 'send';
        this.obj['socket'] = args[0].toInt32();
        this.buffer        = args[1];
        this.length        = args[2];
        this.obj['flag']   = args[3];
        this.obj['bk']     = Thread.backtrace(this.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress);
   },
   onLeave: function (retval) {
        this.obj['numret']    = retval.toInt32();
        Handler_Data(this);
   }
});

Interceptor.attach(funct["sendto"],
{
   onEnter: function (args) {
        this.obj           = {};
        this.obj['plugin'] = 'LLN';
        this.obj['action'] = 'sendto';
        this.obj['socket'] = args[0].toInt32();
        this.buffer        = args[1];
        this.length        = args[2];
        this.obj['flag']   = args[3];
        this.obj['sockad'] = args[4];
        this.obj['lengt']  = args[5];
        this.obj['bk']     = Thread.backtrace(this.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress);
   },
   onLeave: function (retval) {
      this.obj['numret']   = retval.toInt32();
      Handler_Data(this);
   }
});

Interceptor.attach(funct["recv"],
{
    onEnter: function (args) {
        this.obj           = {};
        this.obj['plugin'] = 'LLN';
        this.obj['action'] = 'recv';
        this.obj['socket'] = args[0].toInt32();
        this.buffer        = args[1];
        this.length        = args[2];
        this.obj['flag']   = args[3];
        this.obj['bk']     = Thread.backtrace(this.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress);
   },
   onLeave: function (retval) {
        this.obj['numret']    = retval.toInt32();
        Handler_Data(this);
   }
});

Interceptor.attach(funct["recvfrom"],
{
    onEnter: function (args) {
        this.obj           = {};
        this.obj['plugin'] = 'LLN';
        this.obj['action'] = 'recvfrom';
        this.obj['socket'] = args[0].toInt32();
        this.buffer        = args[1];
        this.length        = args[2];
        this.obj['flag']   = args[3];
        this.obj['sockad'] = args[4];
        this.obj['lengt']  = args[5];
        this.obj['bk']     = Thread.backtrace(this.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress);
   },
   onLeave: function (retval) {
      this.obj['numret']   = retval.toInt32();
      Handler_Data(this);
   }
});
/*

Interceptor.attach(funct["sendmsg"],
{
   onEnter: function (args) {
        this.socket = args[0].toInt32();
        this.buffer = args[1];
        this.length = args[2];
        console.log('Send function called from:\n'+
            Thread.backtrace(this.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n'));
   },
   onLeave: function (retval) {
      this.ret = retval.toInt32();
      console.log('Exit from send\nDumping data --> '+this.ret);
      console.log('Socket: '+this.socket);
      //console.log('----DUMP----\n',hexdump(this.buffer,{length: ret}));
      Data(this);
   }
});
*/
