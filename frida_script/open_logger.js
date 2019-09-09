/*************************************************
** This script allows to log libc open. It is    *
** usefull for retrieving the file created       *
** and/or readed by an application.              *
**************************************************/


/*Resolv address for dynamic hooking*/
function Resolv_Address() {
    var addrs = {};
    var platform = Process.platform
    if (platform == 'linux'){
        try {
            addrs["open"] = Module.getExportByName('libc.so', 'open');
        }catch(err) { 
            addrs["open"] = Module.getExportByName('libc.so.6', 'open');
        }
    }
    return addrs;
}

var addrs= Resolv_Address();
//Attach to libc open function
Interceptor.attach(addrs["open"],
{
    onEnter: function(args) {
        this.pathname = Memory.readCString(args[0]);
        this.flags = args[1];
        // console.log(this.pathname);
    },
    onLeave: function(retval) {
        var ret = retval.toInt32();
        var obj = {};
        obj['plugin'] = "OPN";
        obj['fd'] = ret;
        obj['pathname']=this.pathname
        send(obj, null);
        // console.log(ret + ':  \t' + this.pathname);
    }
});
