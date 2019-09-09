#-*- encoding: utf-8 -*-

import urwid
import re
import subprocess
## Home page view
class Home(urwid.Columns):
    def __init__(self,main_frame,device = None):
        ## This is a window
        self.window = True
        self.label = 'Home page'
        self.isOver = False
        self.main_frame = main_frame
        ## List of devices
        self.devices= urwid.SimpleFocusListWalker([])
        ## List of applications
        self.application = urwid.SimpleFocusListWalker([])
        ## Find the various devices
        for i in self.main_frame.frida.devices:
            b = urwid.Button(i.name)
            urwid.connect_signal(b,'click',self.get_device,i.id)
            self.devices.append(b)
        box_devices=urwid.LineBox(urwid.ListBox(self.devices),title=u"Devices",title_align="center")
        box_app = urwid.LineBox(urwid.ListBox(self.application),title=u"Available applications", title_align="center")
        super(Home,self).__init__([box_devices,box_app])
        if device != None:
            self.get_device(None,device) 
    ## Change the device
    def get_device(self,button,id_dev):
        ## Retrieve the applications list
        apps = self.main_frame.frida.connect(id_dev)
        apps.sort(key = lambda x: x.name)
        for i in apps:
            ## Create the list of applications
            if hasattr(i,'identifier'):
                b = urwid.Button(i.name+' ('+i.identifier+')',on_press = self.ch_app, user_data = i.identifier)
            else:
                b = urwid.Button(i.name+' ('+str(i.pid)+')',on_press = self.ch_app, user_data = i.pid)
            #urwid.connect_signal(b,'click',self.ch_app,i.identifier)
            self.application.append(b)
        ## If the apps length is != 0 -> change focus
        if len(apps) != 0:
            self.focus_position=1
        ## Update the status footer
        if (hasattr(self.main_frame,"status_b")):
            urwid.emit_signal(obj=self.main_frame.status_b,name='status_update')
    ## Change selected application
    def ch_app(self,button,app):
        self.main_frame.frida.app_name = app
        urwid.emit_signal(obj=self.main_frame.status_b,name='status_update')
