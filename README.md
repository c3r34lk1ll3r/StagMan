# StagMan
An helper for mobile applications analysis
## Introduction
`StagMan` is a front end for `frida` (<https://github.com/frida/frida>). It is made for speeding up the reverse engineering activity using useful `frida-script` and allowing to see results in real time.

## Installation

### Dependencies
* Python (version 3)
* python-frida (<https://github.com/frida/frida-python>)
* urwid (<http://urwid.org/>)
* npm (<https://www.npmjs.com/>)
* frida-compile (<https://github.com/frida/frida-compile>)
* frida-fs (<https://github.com/nowsecure/frida-fs>)

For Arch: `yay -S python python-urwid npm python-frida && npm install frida-compile -g && npm install frida-fs -g`

## Usage
After installing the dependencies, simply `git clone <URL>` and run `./stagman.py`

### Command line arguments
```
usage: stagman.py [-h] [-a STRING] [-d STRING] [-p STRING [STRING ...]] [-x]
                  [--headless]

Stagman V.1.0

optional arguments:
  -h, --help            show this help message and exit
  -a STRING, --application STRING
                        Select the application to spawn
  -d STRING, --device STRING
                        Set the device ID
  -p STRING [STRING ...], --plugins STRING [STRING ...]
                        Set the list of plugins
  -x, --respawn         Auto respawn of the application
  --headless            Start in headless mode
  ```
### Urwid GUI
The interface is divided in two main block: a main view and a bottom status information bar.

In the status bar there are this information:
* Plugin enabled
* Device connected
* Application selected
* Respawn: this allow to select the behaviour of frida (respawn the application or hook to the running one).
* Running: if the hooking is in running
#### General commands:
* `h` View the help menu
* `r` Run the selected application
* `s` Stop the frida hooking
* `R` Return to home page
* `v` Windows selection
* `p` Plugins selection
* `x` Toggle respawing behaviour
* `a` Context menu (based on the window)
* `q` Quit
* `n` Open a 'notepad'. This will create a file `ref.txt`. Usefull for taking notes during analysis.
*  `k` Open a terminal. `ctrl d` for detaching.
#### Available plugins (for now only Android)
The available plugins are:
* `TLS Connection`: this plugin hooks `TLS_Read` and `TLS_Write` functions so we can intercept the TLS traffic before the encryption and without using a proxy. 
  * Context menu: 
  * `e` export selected packet. 
  * `E` Export all the packets in PCAP format.
* `Low Level Network`: this plugin hooks to low level network functions (like socket, recv, sendmsg, ecc.) and it allows to intecerpet traffic at lower level. There is also the IPC traffic (unix domain socket). It is a bit heavy so I suggest to stop the hooking before the analysis.
* `File open`: this plugin hooks open system call so we can see the opened files. Thanks to `frida-fs` we can download the file and perform an offline analysis.
  * Context menu: 
  * `e` export selected file.
  * `E` export all the files

Without arguments the application will start in GUI mode. The home page allows to select the device where frida-server is running and, after the selection, a list of the applications.

## TODO:
A lot of things, any help would be appreciate. Roadmap:
- [ ] iOS Support
- [ ] Local server support
- [ ] TCP Frida Server
- [ ] More plugins
- [x] Headless function
- [ ] Auto-analyzer
