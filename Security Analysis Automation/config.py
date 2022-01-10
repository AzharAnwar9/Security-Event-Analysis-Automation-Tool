from cryptography.fernet import Fernet
import ctypes
import os
import sys
import webbrowser

key_dictionary = dict()

def menu():
    print("\n")
    print("-------------------------")
    print("Help & Configuration Menu")
    print("-------------------------")

    print("\nPlease select an option from below : ")
    print("OPTION 1: Help")
    print("OPTION 2: Configure or Re-configure API Keys")
    print("OPTION 0: Exit")
    help_menu(int(input()))

def help_menu(selected_option):
    
    if selected_option == 1 :
        help_module()
    elif selected_option == 2 :
        api_key_config()
    elif selected_option == 0 :
        return
    else :
        print("Incorrect input")
        menu()

def help_module():
    webbrowser.open('https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool/blob/main/README.md')
    menu()

def api_key_config():
    key = Fernet.generate_key()
    f = Fernet(key)
    api_key_filename = 'apiKeyFileName.ini'
    crypto_key_filename = 'cryptoKey.key'
    file_handle = open(api_key_filename, 'w')
    intel_list = ['VirusTotal', 'Abuse IP DB', 'URLScan IO', 'AlienVault OTX', 'Spyse', 'Email Reputation IO']
    for i in range(0, len(intel_list)):
        print("Enter your API Key for " + intel_list[i] + " :")
        api_key = str(input())
        __encrypted_api_key = f.encrypt(api_key.encode()).decode()
        file_handle.write("{} API Key:{}\n".format(intel_list[i],__encrypted_api_key))

    try :
        os_platform = sys.platform
        if (os_platform == 'linux'):
            crypto_key_filename = '.' + crypto_key_filename
        with open(crypto_key_filename, 'w') as file :
            file.write(key.decode())

            if (os_platform == 'win32'):
                ctypes.windll.kernel32.SetFileAttributesW(crypto_key_filename, 2)
            else:
                pass
        print("Configuration Completed!!")
    except PermissionError:
        os.remove(crypto_key_filename)
        print("A Permission error occurred.\n Please re run the script")
        sys.exit()
    menu()

def fetch_api_key():
    api_key_filename = 'apiKeyFileName.ini'
    os_platform = sys.platform
    if (os_platform == 'win32'):
        crypto_key_filename = 'cryptoKey.key'
    else :
        crypto_key_filename = '.cryptoKey.key'
    crypto_key = ''

    with open(crypto_key_filename, 'r') as key:
        crypto_key = key.read().encode()
    
    f = Fernet(crypto_key)

    with open(api_key_filename, 'r') as key:
        keys = key.readlines()
        for mykey in keys:
            api_key = mykey.strip('\n').split(':')
            original_key = f.decrypt(api_key[1].encode()).decode()
            #print(original_key)
            key_dictionary[api_key[0]] = original_key
    
    #print(key_dictionary)
