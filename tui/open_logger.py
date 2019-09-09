#-*- encoding: utf-8 -*-

import urwid
import threading
import queue
import subprocess
import os
import time
from .pop_up import PopUP

## Class for handling files
class int_file():
    def __init__(self,fd,pathname):
        ## Pathname
        self.pathname = pathname
        ## File Descriptor
        self.fd = fd
        if fd == -1 or '/dev' in pathname: 
            ## This way we can check also the files that the application tries to open
            self.contents = b'This file can not be found or it is a device file.'
            self.readed = True
            self.canberead = False
        else:
            self.canberead = True
            self.inreading = False
            self.readed = False
            self.contents = b""
        
## Thread for handling receving data from JS. It will wait on the queue for a new item
class OPN_runner(threading.Thread):
    def __init__(self,files_open):
        super(OPN_runner,self).__init__()
        self.queue = files_open.queue
        self.files = files_open.files
        self.data = files_open.data
        self.print_data = files_open.print_data
        self.main_frame = files_open.main_frame
    def run(self):
        while True:
            ## Wait a new item
            item = self.queue.get()
            self.queue.task_done()
            #print(item)
            ## Handling the object
            message=item[0]
            payload=item[1]
            #print(message)
            #print(payload)
            ## If the message type is 'send' than we know that this is JS data
            if message['type']=='send':
                msg=message['payload']
                pathname = msg['pathname']
                ## If the packet is a reading operation
                if 'end' in msg.keys():
                    ## Reading operation
                    f = self.files[pathname]
                    if msg['end']:
                        f.readed = True
                        f.inreading = False
                    else:
                        f.contents = b''.join([f.contents,payload])
                ## If it is not, it is a open operation
                elif msg['pathname'] not in self.files:
                    pathname = msg['pathname'];
                    f = int_file(msg['fd'],pathname);
                    b = urwid.Button(pathname,on_press = self.print_data,user_data=pathname);
                    self.data.append(b)
                    self.files[pathname] = f
            ## If the message's type is KILL then break and exit the thread
            elif message['type'] == 'KILL':
                break
            else:
                print(message)
            self.main_frame.loop.draw_screen() 
## Main class
class FILE_opener(urwid.Columns):
    ## Class for handling opened file. The data are received by Frida
    def __init__(self,main_frame):
        ## Allowing the TUI to understand if this is a window or not
        self.window = True
        ## Window name
        ## TODO: Is this attribute really usefull?
        self.isOver = False
        self.label = 'File Opened'
        self.main_frame = main_frame
        ## Context menu for action
        self.actionM = ActionMenu(self)
        ## Define the event queue
        self.queue = queue.Queue()
        self.main_frame.plugin_queue['OPN'] = self.queue
        ## Dictionary for storing filenames
        self.files = {}
        self.data = urwid.SimpleFocusListWalker([])
        self.file_list = urwid.ListBox(self.data)
        file_opened=urwid.LineBox(self.file_list)
        self.payload=urwid.Text(u"")
        self.main_view=urwid.LineBox(self.payload,title=u"File contents",title_align="center")
        super(FILE_opener,self).__init__([('weight',0.3,file_opened),('weight',0.6,urwid.Filler(self.main_view,valign='top'))])
        self.runner = OPN_runner(self)
        self.runner.start()
    ## Retrieve and print file's content
    def print_data(self,button,index):
        f = self.files[index]
        ## If it is already readed
        if f.readed:
            dim = len(f.contents)
            if dim < 1024*1024:
                data = str(f.contents).replace('\\n','\n').replace('\\r','')[2:-1]
            else:
                data = "File is too large (~"+str(int(dim/(1024*1024)))+" MB). Export it to analyze."
        ## Reading file
        else:
            if f.inreading == True:
                data = "Loading file..."
            else:
                data = "Loading file, try again in a few seconds"
                ## Start the read
                self.files[index].inreading = True
                self.main_frame.frida.retrieveFile(index)
        self.payload.set_text(data)
    ## Overload the keypress method in order to specify command for this plugin    
    def keypress(self,size,key):
        if key in ('c','C'):
            ## Clear the current history
            self.files.clear()
            del self.data[:]
            self.main_frame.loop.draw_screen()
        if key == 'e':
            ## Export one file
            basename = self.exportFile()
        if key == 'E':
            ## Export all files
            self.exportAll()
        if key == 'a':
            ## View the context menu
            self.main_frame.frame.body = self.actionM.View()
        else:
            return super(FILE_opener,self).keypress(size,key)
    
    ## Export one file
    def exportFile(self):
        ## Retrieve filename (complete path)
        filename = self.file_list.focus.get_label()
        ## The filename is the full path. We need only the filename
        basename = filename.split('/')[-1]
        ## Dialog box
        x = PopUP(self.main_frame,[urwid.Text(u'Exporting file "' +basename+'"...')],allow_close=False)
        self.main_frame.frame.body = x.View()
        ## Copy the file in a local directory
        ## Creating the storing directory
        ## TODO: Modify it in order to allow to store file in their relative path (like files/file.xml or databases/something.sql)
        app_name = self.main_frame.frida.app_name
        b_directory = "./dump/"+app_name+'/files'
        if not os.path.exists(b_directory):
            os.makedirs(b_directory)
        ## If the file is not already readed then launch the frida script for retrieving data
        if self.files[filename].canberead == False:
            x = PopUP(self.main_frame,[urwid.Text(u'File "'+basename+'" can not be readed')])
            self.main_frame.frame.body = x.View()
            return basename
        if self.files[filename].readed == False:
            self.main_frame.frida.retrieveFile(filename)
            while self.files[filename].readed == False:
                ## Polling. This loop wait for reading completation.
                ## TODO: Modify it to handling events instead of polling. Before it we should consider the overhead of inserting an event queue... Usually the file are small so we have only one second delay... 
                time.sleep(1)
        ## Write the file to the hard disk
        ## TODO: Check the various error and exception 
        writeFile=open(b_directory+'/'+basename,'wb')
        writeFile.write(self.files[filename].contents)
        writeFile.close()
        ## Dialog box
        x = PopUP(self.main_frame,[urwid.Text(u'File "'+basename+'" exported!')])
        self.main_frame.frame.body = x.View()
        return basename

    ## Export all the files
    def exportAll(self):
        ## Creating the ProgressBar
        pp = urwid.ProgressBar('','')
        x = PopUP(self.main_frame,[ urwid.Text(u"Dumping all files"),pp],allow_close = False)
        ## Dialog box
        self.main_frame.frame.body = x.View()
        ## Creating the base directory
        ## TODO: The same problem of the single file exportation 
        app_name = self.main_frame.frida.app_name
        b_directory = "./dump/"+app_name+'/files'
        if not os.path.exists(b_directory):
            os.makedirs(b_directory)
        ## Loop over every file that is opened
        cc = len(self.files)
        inx = 0
        for i in list(self.files):
            basename = i .split('/')[-1]
            if self.files[i].canberead == False:
                inx+=1
                pp.set_completion((inx/cc)*100)
                continue
            if self.files[i].readed == False:
                self.main_frame.frida.retrieveFile(i)
                while self.files[i].readed == False:
                    time.sleep(1)
            ## Write the file
            writeFile = open(b_directory+'/'+basename,'wb')
            writeFile.write(self.files[i].contents)
            writeFile.close()
            inx +=1
            ## Update the progress bar 
            pp.set_completion((inx/cc)*100)
        ## Dialog box
        x = PopUP(self.main_frame,[urwid.Text(u'File dumped!'),pp]) 
        self.main_frame.frame.body = x.View()
## Context menu
class ActionMenu(PopUP):
    def __init__(self,files):
        text = ["Export the selected file (<e>)", "Export all files (<E>)"]
        self.files = files
        opt = []
        for i in text:
            opt.append(urwid.Button(i,on_press=self.Action,user_data = i.split('<')[1].split('>')[0]))
        super(ActionMenu,self).__init__(files.main_frame,opt,'Action menu')
    def Action(self,key,name):
        if name == 'e':
            ## Export one file
            self.files.exportFile()
            super(ActionMenu,self).keypress(None,'esc')
        elif name == 'E':
            ## Export files
            self.files.exportAll()
            super(ActionMenu,self).keypress(None,'esc')
