import urwid
import os
class Notebook(urwid.Filler):
    ## Class for notebook inside the application. This is usefull for taking notes during the analysis.

    def __init__(self, main_frame):
        self.window = True
        self.isOver = True
        self.label = "Notebook"
        ## TODO: Allow the changing of the filename
        self.filename = './ref.txt'
        self.main_frame = main_frame
        super(Notebook,self).__init__(urwid.Edit(multiline=True,align='left',allow_tab = True),valign='top')
        if os.path.isfile(self.filename) == True:
            readf=open(self.filename,'r')
            r = readf.read()
            self.original_widget.insert_text(str(r))
            readf.close()

    def View(self):
        self.overlay = urwid.Overlay(urwid.LineBox(self,title = 'Notebook',title_align='center'), self.main_frame.main_view,align = 'center',width = 50,valign='middle',height=40) 
        return self.overlay

    def keypress(self,size,key):
        ## When the notebook is closed the new data are saved
        if key == 'esc':
            writef = open(self.filename,'w')
            writef.write(self.original_widget.get_edit_text())
            writef.close()
            self.main_frame.frame.body=self.overlay.contents[0][0]
        else:
            return super(Notebook,self).keypress(size,key)
