import re
import tkinter
from tkinter import filedialog

def menu():
    print("\n")
    print("----------------------------")
    print("IOCs Sanitization for Emails")
    print("----------------------------")

    print("\nPlease select an option from below : ")
    print("OPTION 1: Single Input")
    print("OPTION 2: Upload a file with multiple values(Bulk Upload)")
    print("OPTION 0: Exit")
    sanitize_menu(int(input()))

def sanitize_menu(selected_option):
    
    if selected_option == 1 :
        ioc_sanitize()
    elif selected_option == 2 :
        bulk_ioc_sanitize()
    elif selected_option == 0 :
        return
    else :
        print("Incorrect input")
        menu()

def bulk_ioc_sanitize():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(title="Select a file(.txt)")
    ioclist = list()
    with open(root.filename) as file :
        ioclist = [line.rstrip() for line in file]
    
    f = open('results.txt', 'w')
    for ioc in ioclist:
        final_ioc = re.sub(r"\.", "[.]", ioc)
        final_ioc = re.sub("http://", "hxxp://", final_ioc)
        final_ioc = re.sub("https://", "hxxps://", final_ioc)
        final_ioc = re.sub(r"\:", "[:]", final_ioc)
        f.write(final_ioc.strip() + "\n")
    root.destroy()
    menu()

def ioc_sanitize():
    ioc = str(input("Enter IoC(IP/Domain/URL) to be sanitized :"))

    final_ioc = re.sub(r"\.", "[.]", ioc)
    final_ioc = re.sub("http://", "hxxp://", final_ioc)
    final_ioc = re.sub("https://", "hxxps://", final_ioc)
    final_ioc = re.sub(r"\:", "[:]", final_ioc)
    
    print("\n Sanitized Output :", final_ioc)
    menu()