import brand_monit
import config
import dns_option
import file_sandbox
import phishing_analysis
import reputation_check
import sanitize
import time
import url_decoding

def main_switch(selected_option):
    if selected_option == 0 :
        exit()
    if selected_option == 1 :
        reputation_check.input_validate()
    if selected_option == 2 :
        dns_option.menu()
    if selected_option == 3 :
        phishing_analysis.menu()
    if selected_option == 4 :
        url_decoding.menu()
    if selected_option == 5 :
        file_sandbox.file_sandbox()
    if selected_option == 6 :
        sanitize.menu()
    if selected_option == 7 :
        brand_monit.menu()
    if selected_option == 8 :
        config.menu()

if __name__ == '__main__' :
    print("\n")
    print("----------------------------------------")
    print("SECURITY EVENT ANALYSIS AUTOMATION TOOL")
    print("----------------------------------------")
    print("\nThe SOC Analyst's tool to automate"
    "\nthe investigation and validation of possible "
    "\nIndicators of Compromise (IOCs)")
    time.sleep(1)
    while True:
        try:
            config.fetch_api_key()
        except:
            print("\n\nHey there, user!!")
            print("\nLooks like you have run this script for the first time or you dont have sufficient permissions to access the encryption key or your key file has been removed.")
            print("\nDirecting you to help & Configuration/Re-configuration menu to configure your script, if you have already configured you keys, please rerun tool with sufficient privileges")
            config.menu()
            config.fetch_api_key()
            
        print("\nPlease select an option from below : ")
        print("OPTION 1: Reputation/Blocklist Check (IPs, Domains, URLs, Hashes)")
        print("OPTION 2: DNS/WHOIS Lookup Options")
        print("OPTION 3: Email Security (Phishing Email Analysis)")
        print("OPTION 4: URL Decoding for Investigation")
        print("OPTION 5: File Upload for Sandboxing")
        print("OPTION 6: Sanitization of IOCs for email")
        print("OPTION 7: Brand Monitoring & Analysis")
        print("OPTION 8: Help & Configuration/Re-configuration")
        print("OPTION 0: Exit Tool")
        
        selected_option=int(input())
        if 0 <= selected_option < 9:
            main_switch(selected_option)
        else :
            print("Please select correct option numer as mentioned")
