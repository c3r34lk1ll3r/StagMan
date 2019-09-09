console.log('!!!')
var p = Process.getCurrentThreadId();
console.log(p)
Stalker.follow(Process.getCurrentThreadId(), {
    events: {
        call: true,
        ret: false,
        exec: false,
        block: false,
        compiled: false
    },
    onReceive: function (events) {
        console.log('???')
  }
});
