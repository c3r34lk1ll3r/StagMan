import urwid

## Main class for creating popup window

class PopUP(urwid.Pile):
    def __init__(self, main_frame,original_widgets, Title="",allow_close=True):
        ## This is not a windows itself
        #self.window = False
        self.main_frame = main_frame
        self.title = Title
        ## TODO: Move the close button to the bottom
        self.ac = allow_close
        if allow_close:
            original_widgets.append(urwid.Divider(top=3))
            original_widgets.append(urwid.Button('Close',on_press=self.Close))
        super(PopUP,self).__init__(original_widgets)
    
    def Close(self, useless):
        ## Close the view
        self.main_frame.frame.body = self.overlay.contents[0][0]

    def View(self):
        ## TODO: The width and heigth should be computed in runtime
        self.overlay = urwid.Overlay(urwid.LineBox(urwid.Filler(self,valign='top',top=1),title=self.title,title_align='center'), self.main_frame.main_view,align = 'center',width = 70,valign='middle',height=30) 
        return self.overlay
    ## keypress for exiting with esc
    def keypress(self,size,key):
        if key == 'esc':    
            if self.ac:
                self.main_frame.frame.body=self.overlay.contents[0][0]
        else:
            return super(PopUP,self).keypress(size,key)
