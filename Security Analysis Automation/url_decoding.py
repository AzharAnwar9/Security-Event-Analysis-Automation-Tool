import base64
import re
import requests
import urllib.parse

def menu():
    print("\n")
    print("------------------------------")
    print("URL Decoding for Investigation")
    print("------------------------------")

    print("\nPlease select an option from below : ")
    print("OPTION 1: URL Decoder")
    print("OPTION 2: Base64 Decoder")
    print("OPTION 3: Office365 SafeLink Decoder")
    print("OPTION 4: UnShorten the URL")
    print("OPTION 0: Exit")
    url_decoding_menu(int(input()))

def url_decoding_menu(selected_option):
    
    if selected_option == 1 :
        url_decoder()
    elif selected_option == 2 :
        base64_decoder()
    elif selected_option == 3 :
        office365_decoder()
    elif selected_option == 4 :
        unshorten_url()
    elif selected_option == 0 :
        return
    else :
        print("Incorrect input")
        menu()

def url_decoder():
    print("\n")
    url = str(input("Enter URL to be decoded :"))

    print("\n")
    print("------------------")
    print("SIMPLE URL DECODER")
    print("------------------")
    try:
        decoded_url = urllib.parse.unquote(url)
        print("Decoded URL :", decoded_url)
    except:
        print("Invalid URL inserted")
        url_decoder()
    menu()

def base64_decoder():
    print("\n")
    url = str(input("Enter URL to be decoded :"))

    print("\n")
    print("---------------------")
    print("SIMPLE BASE64 DECODER")
    print("---------------------")
    
    try:
        b64_decoded = str(base64.b64decode(url))
        decoded_url = re.split("'", b64_decoded)[1]
        print("Decoded URL :", decoded_url)
    except:
        print("Invalid URL inserted")
        base64_decoder()
    menu()

def office365_decoder():
    print("\n")
    url = str(input("Enter URL to be decoded :"))

    print("\n")
    print("-------------------------------")
    print("Office 365 SAFELINK URL DECODER")
    print("-------------------------------")
    try:
        decoded_result = urllib.parse.unquote(url)
        decoded_url = decoded_result.split("=")
        final_url = decoded_url[1]
        if len(decoded_url) > 2 :
            for i in range(2, len(decoded_url)):
                final_url = final_url + "=" + decoded_url[i]
        print("Decoded URL :", final_url)
    except:
        print("Invalid URL inserted")
        office365_decoder()
    menu()

def unshorten_url():
    print("\n")
    url = str(input("Enter Shortened URL to be Unshortened :"))

    print("\n")
    print("---------------------")
    print("SIMPLE URL UNSHORTNER")
    print("---------------------")

    try:
        results = requests.get('https://unshorten.me/s/' + url)
        print("Decoded URL :", str(results.text))
    except:
        print("Invalid URL inserted")
        unshorten_url()
    menu()