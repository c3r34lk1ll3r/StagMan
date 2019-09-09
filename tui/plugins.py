import urwid
from .pop_up import PopUP
## Class for handling activation/deactivation of plugins
class Plugins(PopUP):
    def __init__(self, main_frame,enabled):
        ## This is not a window, is an overlay
        self.window = False
        ## List of plugins. If a new plugin needs to be addedd than a new dictionary entry should be inserted.
        ## NOTE: The key is the plugin name. The data is the JS path file
        self.plugins_list={'TLS Logger':'frida_script/tls_logger.js','Low Level Network':'frida_script/ll_net.js','File Open':'frida_script/open_logger.js'}
        self.frida = main_frame.frida
        pile = []
        for i in self.plugins_list:
            if i in enabled:
                st = True
                self.frida.plugins.append(self.plugins_list[i])
            else:
                st = False
            c = urwid.CheckBox(i,state=st,on_state_change = self.change_plugin,user_data = i)
            pile.append(c)
        urwid.emit_signal(main_frame.status_b,'status_update') 
        super(Plugins,self).__init__(main_frame,pile,"Available Plugins")
    ## Modify the plugin
    def change_plugin(self,key, status, name):
        if self.plugins_list[name] in self.frida.plugins and status==False:
            self.frida.plugins.remove(self.plugins_list[name])
        elif self.plugins_list[name] not in self.frida.plugins and status == True:
            self.frida.plugins.append(self.plugins_list[name])
        ## Update the status bar
        urwid.emit_signal(self.main_frame.status_b,'status_update') 
