/*************************************************
** This is a particular script. We use it to     *
** retrieve data from the device's storage. It   *
** will be compile (only once) and, thanks to    *
** 'seed' we modify it to retrieve the correct   *
** file. We are aware of the hafulness of this   *
** behaviour but we are waiting for a            *
** arguments-passing mechanism                   *
**************************************************/

'use strict';
setImmediate(function() { 
    const fs = require("frida-fs");
    var obj = {};
    obj['plugin']='OPN';
    obj['pathname'] = '/path/to/file/to/retrieve';
    try {
    var fileStream = fs.createReadStream('/path/to/file/to/retrieve');
    } catch(err) {
        obj['end'] = true;
        send(obj,null);
    }
    fileStream.on('data', function(chunk){
            obj['end']=false;
            send(obj,chunk);
    });
    fileStream.on('end',function(){
            obj['end'] = true;
            send(obj,null)
    });

    
 });
