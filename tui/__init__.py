#!/usr/bin/env python
# -*- coding: utf-8 -*-
import urwid
import threading

#from .menu import Menu
from .tls_connection import TLS_connection
from .ll_network import LL_network
from .home_page import Home 
from .plugins import Plugins
from .status_bar import StatusBar
from .view import WindowsList
from .help import Help
from .notebook import Notebook
from .open_logger import FILE_opener
from .terminal import Term

class Dispatcher(threading.Thread):
    # This class acts like a event dispatcher. We take the queue of events, handled by Frida, and a plugin's queue handled by each plugin.
    def __init__(self,events,plugin_queue):
        super(Dispatcher,self).__init__()
        self.events = events
        self.plugin_queue=plugin_queue
   
    def run(self):
        # We loop over the frida's queue and resend the various event to the various plugin manager
        # stop = False
        while True:
            event = self.events.get()
            # This is a self-generated event that allows the clean killing of the various threads
            if event[0]['type'] == 'KILL':
                #stop = True
                for i in self.plugin_queue:
                    self.plugin_queue[i].put(event)
                self.events.task_done()
                break
            ## Take the event and put in the correct queue. The binding between Frida JS and python code is based on the 'plugin' key setted by the script 
            queue = event[0]['payload']['plugin']
            self.plugin_queue[queue].put(event) 
            self.events.task_done()

class ncgui:
    """Basic class for TUI"""
    def __init__(self,list_event,frida,enabled_plugin,device = None):
        """list_event: queue for moving data from frida to python without blocking frida
            frida: FridaHandler instance"""
        
        ## Palette
        #palette = [
        #    ('banner', 'black', 'light gray'),
        #    ('streak', 'black', 'dark red'),
        #    ('bg', 'black', 'dark blue'),]i

        ## This queue should make more easier the creation of new plugins. It is a dictionary of queues. The key index is the plugin name; the content in the queue used by the plugin
        self.plugin_queue = {}
        self.list_event = list_event
        ## Dispatcher. This class is a thread in order avoiding blocking Frida.
        disp = Dispatcher(list_event,self.plugin_queue)
        disp.start()
        ## Storing the Frida Handler
        self.frida=frida
        ## Various TUI bodies. We create one time and change the parameter
        self.bodies = {}
        self.bodies['homepage'] = Home(self,device)
        
        ## Set the main view in homepage
        self.main_view = self.bodies['homepage']
        self.status_b = StatusBar(self.frida)
        status_bar = urwid.LineBox(self.status_b,title="",bline="",lline='',rline='',trcorner='─',tlcorner='─',)
        ## Create main container
        self.frame = urwid.Frame(self.main_view,header=None,footer=status_bar)
        ## Creating loop manager
        self.loop = urwid.MainLoop(self.frame,unhandled_input=self.key_handler,pop_ups=True)
        self.bodies['tls_connection'] = TLS_connection(self)
        self.bodies['ll_connection'] = LL_network(self)
        self.bodies['open']= FILE_opener(self)
        self.bodies['help'] = Help(self)
        self.bodies['notebook'] = Notebook(self)
        self.bodies['terminal'] = Term(["/bin/bash"],self)
        self.bodies['view'] = WindowsList(self) 
        self.bodies['plugins'] = Plugins(self,enabled_plugin)
        
    
    def change_body(self, body):
        if self.bodies[body].isOver:
            self.frame.body = self.bodies[body].View()
        else:
            self.main_view = self.bodies[body]
            self.frame.body = self.bodies[body]
    
    ## Starting the main loop and TUI 
    def start(self):
        self.loop.run()   
    
    ## Handling the key general key bindings 
    def key_handler(self,key):
        ## Quit from the application
        if key in ('q', 'Q'):
            self.list_event.put([{'type':'KILL'},None])
            raise urwid.ExitMainLoop()
        ##Toggle respawn
        elif key in ('x','X'):
            self.status_b.status_respawn.toggle_state()
        ## Enable/Disable plugins
        elif key in ('p','P'):
            self.frame.body = self.bodies['plugins'].View()
        elif key == 'r':
            ##Run the selected application
            self.frida.run()
            urwid.emit_signal(self.status_b,'status_update')
            self.status_b.status_running.set_state(self.frida.isRunning,do_callback = False)
        ## Stop frida
        elif key == 's':
            self.frida.stopFrida()
            self.status_b.status_running.set_state(self.frida.isRunning, do_callback = False)
            urwid.emit_signal(self.status_b,'status_update')
        ## Back to home page
        elif key == 'R':
            self.frame.body = self.bodies['homepage']
        ## Change view
        elif key in ('v','V'):
            self.frame.body = self.bodies['view'].View()
        ## Help
        elif key in ('h','H'):
            self.frame.body = self.bodies['help'].View()
        elif key in ('n','N'):
            self.frame.body = self.bodies['notebook'].View()
        elif key=='k':
            self.frame.body = self.bodies['terminal'].View()
