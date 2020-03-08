#!/usr/bin/python3

from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter.simpledialog import askstring
from tkinter import filedialog, messagebox
from tkinter.messagebox import showinfo

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
 
BLOCK_SIZE = 16
pad = lambda s: s.decode() + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
 
def encrypt(raw, password):
    # private_key = hashlib.sha256(password.encode("utf-8")).digest()
    # print(raw)
    raw = raw.encode()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(password, AES.MODE_CBC, iv)
    raw = raw.encode()
    return base64.b64encode(iv + cipher.encrypt(raw))
 
def decrypt(enc, password):
    # private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(password, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

def hasher(data):
    return hashlib.sha256(data.encode("utf-8")).digest()


global filename
filename = ''
global password
password = ''

def askPasswd():
    global password

    inputPasswd = askstring('Password', 'Enter your password')
    password = hasher(inputPasswd)
    del inputPasswd #for not storing password in plain text

def save(event=False):
    global filename 

    if not password:
        askPasswd()

    content = txt.get('1.0', END)
    if not filename:
        # filename = askstring(window, 'File name:')
        filename = filedialog.asksaveasfilename(initialdir = "/home",title = "Select file's name and location",filetypes = (("Text file","*.txt"),("all files","*.*")))
    if type(filename) != tuple and filename:    
        window.title("Secure Text Editor-{}".format(filename))

        content = encrypt(content, password).decode()

        with open(filename, 'w+') as f:
            f.write(content)

def saveAs(event=False):
    global filename 

    askPasswd()

    content = txt.get('1.0', END)
    filename = filedialog.asksaveasfilename(initialdir = "/home",title = "Select file's name and location",filetypes = (("Text file","*.txt"),("all files","*.*")))
    
    if type(filename) != tuple and filename:
        window.title("Secure Text Editor-{}".format(filename))

        content = encrypt(content, password).decode()

        with open(filename, 'w+') as f:
            f.write(content)
    
def new(event=False):
    global filename 

    askPasswd()

    filename = filedialog.asksaveasfilename(initialdir = "/home",title = "Select file's name and location",filetypes = (("Text file","*.txt"),("all files","*.*")))
    if type(filename) != tuple and filename:
        window.title("Secure Text Editor-{}".format(filename))

        f = open(filename, 'w+')
        f.close()

def openfile(event=False):
    global filename

    askPasswd()

    filename = filedialog.askopenfilename(initialdir = "/home",title = "Select file",filetypes = (("Text file","*.txt"), ("all files","*.*")))

    if type(filename) != tuple and filename:
        window.title("Secure Text Editor-{}".format(filename))

        with open(filename, 'r') as f:
            content = f.read()

        content = decrypt(content, password).decode()

        txt.delete('1.0', END)
        txt.insert('1.0', content)

def exitFile():
    msg = messagebox.askyesnocancel("Confirm", "Your work could not be saved. Do you want to save?")
    if  msg == True:
        save()
        if filename:
            window.quit()
    elif msg == False:
        window.quit()
    else:
        pass

def about():
    aboutText = '''This text editor encrypts the text you write automatically on saving with your personal password, and decrypts it when opened. It doesn store anywhere your passwords (nor as plain text or hashed) and the plain text, therefore, if you loose or forget your password, you won't be able to read your ecrypted files. A password recovery tool might be implemented on a future, but that will probably decrease the security.
    '''

    aboutInfo = Toplevel(window)
    aboutInfo.title('About STE')

    aboutTxt = ScrolledText(aboutInfo, padx=50, pady=70, wrap=WORD)
    aboutTxt.pack(expand=True, fill=BOTH, padx=60, pady=20)
    aboutTxt.insert('1.0', aboutText)

    aboutInfo.mainloop()

def commands():
    commandsText = '''  Crtl + s --> Save
    Crtl + o --> open
    Crtl + n --> new
    Crtl + c --> copy
    Crtl + v --> paste
    Crtl + x --> cut
    '''

    commandsInfo = Toplevel(window)
    commandsInfo.title('Commands')

    commandsTxt = ScrolledText(commandsInfo, padx=50, pady=70, wrap=WORD)
    commandsTxt.pack(expand=True, fill=BOTH, padx=60, pady=20)
    commandsTxt.insert('1.0', commandsText)

    commandsInfo.mainloop()



window = Tk()
window.geometry('1000x800')

# inputPasswd = askstring('Password', 'Enter your password')
# global password
# password = hasher(inputPasswd)
# del inputPasswd #for not storing password in plain text


if filename:
    window.title("Secure Text Editor-{}".format(filename))
else:
    window.title('Secure Text Editor')

menu = Menu(window)

filemenu = Menu(menu)
menu.add_cascade(label="File", menu=filemenu)
filemenu.add_command(label="New", command=new)
filemenu.add_command(label="Open", command=openfile)
filemenu.add_separator()
filemenu.add_command(label="Save", command=save)
filemenu.add_command(label="Save as", command=saveAs)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=exitFile)

helpmenu = Menu(menu)
menu.add_cascade(label="Help", menu=helpmenu)
helpmenu.add_command(label="Commands", command=commands)
helpmenu.add_command(label="About...", command=about)

window.config(menu=menu)

global txt
# var = StringVar()
txt = ScrolledText(window, padx=50, pady=70, wrap=WORD)
txt.pack(expand=True, fill=BOTH, padx=60, pady=20)

# print(txt.count('1.0', END, chars=True, update=True))

window.protocol('WM_DELETE_WINDOW', exitFile)
window.bind('<Control-s>', save)
window.bind('<Control-o>', openfile)
window.bind('<Control-n>', new)

window.mainloop()