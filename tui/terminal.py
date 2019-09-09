import urwid

class Term(urwid.Terminal):
    def __init__(self,com,main_frame):
        self.window = True
        self.isOver = True
        self.label = com[0]
        self.main_frame = main_frame
        self.comm = com
        super(Term,self).__init__(command=com,main_loop = self.main_frame.loop)

    def View(self):
        ## TODO: The size should be computed in run time
        self.overlay = urwid.Overlay(urwid.LineBox(self,title = str(self.label),title_align='center'), self.main_frame.main_view,align = 'center',width = 150,valign='middle',height=40) 
        return self.overlay
    def keypress(self,k,key):
        if key == 'ctrl d':
            self.main_frame.frame.body = self.overlay.contents[0][0]
        else:
            return super(Term,self).keypress(k,key)

