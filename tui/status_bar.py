import urwid
## Footer of the main TUI.
class StatusBar(urwid.WidgetWrap):
    ## This class handles status_update signal in order to update itself
    signals = ['status_update']
    def __init__(self,frida):
        self.frida = frida
        self.status_respawn = urwid.CheckBox('Respawn', state = frida.respawn,on_state_change=self.change_respawn)
        self.status_running = urwid.CheckBox('Running', state = frida.isRunning, on_state_change=None)
        self.plugin = urwid.Text(u"Enabled plugins\n"+str(frida.plugins))
        if (hasattr(self.frida,'device')):
            self.device = urwid.Text(u"Device\n"+str(frida.device))
        else:
            self.device = urwid.Text(u"Device\n")
        if (hasattr(self.frida,'app_name')):
            self.app_name = urwid.Text(u"Application name\n"+str(frida.app_name))
        else:
            self.app_name = urwid.Text(u"Application name\n")
        self.status_text = [self.plugin,self.device,self.app_name,urwid.Pile([self.status_respawn,self.status_running])]
        urwid.connect_signal(self,'status_update',self.update_status) 
        super(StatusBar,self).__init__(urwid.Columns(self.status_text))
    ## Change application respwaing
    def change_respawn(self,key,i):
        self.frida.respawn = i
    def update_status(self):
        self.plugin.set_text(u"Enabled plugins\n"+str(self.frida.plugins))
        if (hasattr(self.frida,'device')):
            self.device.set_text(u"Device\n"+str(self.frida.device))
        if (hasattr(self.frida,'app_name')):
            self.app_name.set_text(u"Application name\n"+str(self.frida.app_name))

