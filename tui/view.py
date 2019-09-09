import urwid
from .pop_up import PopUP
## Class for handling windows selection
class WindowsList(PopUP):
    def __init__(self, main_frame):
        self.window = False
        self.window_list = main_frame.bodies
        pile = []
        ## This plugin works by itself. It takes the window list defined in the main_frame (bodies) and it creates the menu
        for i in self.window_list:
            if self.window_list[i].window == True:
                c = urwid.Button(self.window_list[i].label,on_press = self.change_view, user_data = i)
                pile.append(c)
        self.main_frame = main_frame
        super(WindowsList,self).__init__(main_frame,pile,"Available Windows")

    def change_view(self,key, name):
        self.main_frame.change_body(name)
