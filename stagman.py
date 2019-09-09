#!/usr/bin/env python
import frida
import sys
import signal
import queue
import threading
import tui
import argparse
import os
import subprocess
import time
data_list = queue.Queue()

## Handler for frida
class FridaHandler():
    ## TODO: Handling the error of frida
    def __init__(self,event):
        self.devices=frida.enumerate_devices()
        self.event_queue = event
        self.app_name = ""
        self.respawn = True
        self.plugins =[]
        self.scripts = []
        self.isRunning = False
        self.callback = self.recv_data
    def connect(self,device_id):
        """ Connect to a device """
        try:
            self.device = frida.get_device(device_id)
            if device_id == 'local':
                self.apps = self.device.enumerate_processes()
            else:
                self.apps = self.device.enumerate_applications()
            return self.apps
        except frida.InvalidArgumentError as e:
            self.device = 'Device \'' + device_id+'\' not found'
        except frida.ServerNotRunningError as e:
            self.device = 'Device \''+device_id+'\' haven\'t an instance of frida-server running'
        return []

    def run(self):
        """ Running the application in the device.
            respawn: True/False -> Choose if the application should be spawned every launch or 'hook' to a launched apps.
            plugins: List of javascript filename """
        ## Check if the device is connected and frida-server is reacheable
        if type(self.device) is not frida.core.Device:
            return
        spawned = False
        ## Check if respawn the application or hooking to a running one
        if (self.respawn):
            try:
                self.pid = self.device.spawn(self.app_name)
                self.process = self.device.attach(self.pid)
                spawned = True
            except frida.ExecutableNotFoundError as e:
                self.app_name = "\'"+self.app_name+'\' not found'
                return
            except frida.NotSupportedError as e:
                self.app_name = '\''+self.app_name+'\' not supported'
                return
        else:
            lista=self.device.enumerate_processes()
            flag = False
            for i in lista:
                if i.name == self.app_name:
                    flag = True
                    self.pid = i.pid
                    break
            if flag == True:
                self.process = self.device.attach(self.pid)
            else:
                ## If the application can not be found in the process then spawn a new one
                try:
                    self.pid = self.device.spawn(self.app_name)
                    self.process = self.device.attach(self.pid)
                    spawned = True
                except frida.ExecutableNotFoundError as e:
                    self.app_name = '\''+self.app_name+'\' not found'
                    return
                except frida.NotSupportedError as e:
                    self.app_name = '\''+self.app_name+'\' not supported'
                    return
        ## Load the script plugin
        self.scripts = []
        for i in self.plugins:
            script = self.process.create_script(open(i).read())
            script.on('message',self.callback)
            script.load()
            self.scripts.append(script)
        ## If the application is a new-spawned one resume the execution
        if spawned:
            self.device.resume(self.pid)
        self.isRunning = True
    # Run without the CLI, assumes scripts, apps and device already set
    # in the frida class. It will take the output of the scripts and dump
    # it to stdout
    def stopFrida(self):
        for i in self.scripts:
            i.unload()
        self.isRunning = False
    def run_headless(self,enabled,dev):
        apps=self.connect(dev)
        print(str(self.device))
        if type(self.device) != frida.core.Device:
            return
        self.plugins = enabled
        print('Enabled plugin:')
        for i in self.plugins:
            print('\t->'+i)
        self.callback = self.dump_data
        self.run()
        if self.isRunning == False:
            print('Error: running '+self.app_name) 
            return 
        print('Running '+self.app_name)
        while True:
            time.sleep(1)
    def dump_data(self, message, payload):
        print(message)
        print(payload)

    def retrieveFile(self,pathname):
        ## TODO: Handling frida error
        ## First, Check if compiled file already exist
        script_file = './frida_script/retrieve_file.js'
        cScript_file = './frida_script/retrieve_fileC.js'
        if not os.path.isfile(cScript_file):
           ## Compile file
           subprocess.check_output(['frida-compile',script_file,'-o',cScript_file])
        ## Modify the pathname
        placeholder = '\/path\/to\/file\/to\/retrieve'
        pathname = pathname.replace('/','\/')
        sed = 'sed s/'+placeholder+'/'+pathname+'/g ' + cScript_file 
        x = subprocess.check_output(sed.split())
        ## Create frida script and execute it
        self.script = self.process.create_script(source=x.decode('utf-8'))
        self.script.on('message',self.recv_data)
        self.script.load()

    # Callback for handling the frida data.
    # This function allows to use one function to handle all the different plugin.
    # This way, the frida class is agnostic of the usage of the script loaded.
    def recv_data(self,message,payload):
        if message['type'] != 'error': 
            self.event_queue.put([message,payload])

def main(options):
    frida = FridaHandler(data_list)
    enabled_plugin = []
    dev = None
    if (options.app):
        frida.app_name = options.app
    if (options.device):
        #apps=frida.connect(options.device)
        dev = options.device
    if (options.plugins):
       enabled_plugin = options.plugins 
    frida.respawn = options.respawn
    # Start in headless mode or start the CLI
    if options.headless:
        frida.run_headless(enabled_plugin,dev)
    else:
        ## Creating the main object.
        tux = tui.ncgui(data_list,frida,enabled_plugin,dev)
        ## Starting the TUI
        tux.start()

if __name__ == '__main__':
    #Definition of the options
    parser = argparse.ArgumentParser(description="Stagman V.1.0")
    parser.add_argument(
        "-a", "--application", dest="app",
        metavar="STRING",
        help="Select the application to spawn")

    parser.add_argument(
        "-d", "--device", dest="device",
        metavar="STRING",
        help="Set the device ID")

    parser.add_argument(
        "-p", "--plugins", dest="plugins", default="",
        nargs='+', metavar="STRING",
        help="Set the list of plugins")
    parser.add_argument(
        "-x", "--respawn", action="store_false",default=True
        ,help="Auto respawn of the application")
    parser.add_argument(
        "--headless", action="store_true",
        help="Start in headless mode")

    options = parser.parse_args()
    main(options)

# Vim set tabstop=4
