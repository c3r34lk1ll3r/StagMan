import urwid
from .pop_up import PopUP

class Help(PopUP):
    def __init__(self, main_frame):
        ## This is not a windows itself
        self.window = False
        ## Help Text 
        text = ["< h >    This help", "< r >    Run the selected application","< s >    Stop the hooking","< R >    Return to home page","< v >    Windows selection","< p >    Plugins selection", "< x >    Toggle respawing","< a >    Context/Action menu (available inside the plugin view)","< q >    Quit"]
        opt = []
        ## Create the text
        for i in text:
            opt.append(urwid.Text(i))
        super(Help,self).__init__(main_frame,opt,'General Help')
