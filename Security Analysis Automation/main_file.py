import json
import requests
import re
import dns_option
import reputation_check
import time

def main_switch(selected_option):
    if selected_option == 0 :
        exit()
    if selected_option == 1 :
        reputation_check.input_validate()
    if selected_option == 2 :
        dns_option.menu()
    if selected_option == 3 :
        print("Phishing Email Analyis")
    if selected_option == 4 :
        print("URL Decoding/Encoding")
    if selected_option == 5 :
        print("File Upload for Sandboxing")
    if selected_option == 6 :
        print("Sanitization of IOCs for Email")
    if selected_option == 7 :
        print("Extras")    

if __name__ == '__main__' :
    print("\n")
    print("----------------------------------------")
    print("SECURITY EVENT ANALYSIS AUTOMATION TOOL")
    print("----------------------------------------")
    print("\nThe SOC Analyst's all-in-one tool to "
    "\nautomate the investigation and validation of possible "
    "\nIndicators of Compromise (IOCs)")
    time.sleep(1)
    while True:
        print("\nPlease select an option from below : ")
        print("OPTION 1: Reputation Check (IPs, Domains, URLs, Hashes)")
        print("OPTION 2: DNS Options")
        print("OPTION 3: Phishing Email Analysis")
        print("OPTION 4: URL Decoding/Encoding")
        print("OPTION 5: File Upload for Sandboxing")
        print("OPTION 6: Sanitization of IOCs for email")
        print("OPTION 7: Extras")
        print("OPTION 0: Exit Tool")

        selected_option=int(input())
        if 0 <= selected_option < 8:
            main_switch(selected_option)
        else :
            print("Please select correct option numer as mentioned")