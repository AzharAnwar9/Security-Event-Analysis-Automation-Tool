import hashlib
import reputation_check
import tkinter
from tkinter import filedialog

def file_sandbox():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    fileHash = hasher.hexdigest()
    print("MD5 Hash: " + fileHash)
    root.destroy()
    reputation_check.check_hash_reputation(fileHash)
    return