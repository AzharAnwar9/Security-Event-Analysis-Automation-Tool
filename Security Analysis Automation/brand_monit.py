import config
import dns_option
import reputation_check
import requests
import time

def menu():
    print("\n")
    print("---------------------------")
    print("Brand Monitoring & Analysis")
    print("---------------------------")

    print("\nPlease select an option from below : ")
    print("OPTION 1: Check for Geography of URL")
    print("OPTION 2: Check for main UI of URL/Social Media Account/Mobile App")
    print("OPTION 3: Check for URL Reputation")
    print("OPTION 0: Exit")
    brand_monit_menu(int(input()))

def brand_monit_menu(selected_option):
    
    if selected_option == 1 :
        url_geolocation()
    elif selected_option == 2 :
        screenshot()
    elif selected_option == 3 :
        url_reputation_check()
    elif selected_option == 0 :
        return
    else :
        print("Incorrect input")
        menu()

def url_geolocation():
    dns_option.dnslookup()
    menu()

def screenshot():
    url = str(input("Enter the URL to check :")).strip()
    print("\n")
    print("------------------")
    print("URL SCAN IO REPORT")
    print("------------------")
    
    urlscanapikey = config.key_dictionary['URLScan IO API Key']
    scan_type = 'private'
    type = str(input('''Do you want to run a public scan?[y/N]
    A public scan result will be available in URL SCAN IO DB and searchable on open internet.
    Default is private.'''))

    if type == 'y':
        scan_type = 'public'
    
    headers = {'Content-Type': 'application/json','API-Key': urlscanapikey}
    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data='{"url": "%s", "%s": "on"}' % (url, scan_type)).json()
        print(response['message'])
        print("Visibility :",response['visibility'])
        print("Unique ID  :", response['uuid'])

        if 'successful' in response['message']:
            print("Scanning %s." %url)
            print("\n")
            print("We're waiting for this website to finish loading. This might take a minute.\nYou will automatically be redirected to the result, you do not have to rerun any command!")
            time.sleep(50)
            final_response = requests.get('https://urlscan.io/api/v1/result/%s/' %response['uuid']).json()
            #print(final_response)
            print("\n")
            print("------------------")
            print("URL SCAN IO REPORT")
            print("------------------")
            print("\n")
            print("URL Scanned       :", str(final_response['task']['url']))
            print("Overall Score     :", str(final_response['verdicts']['overall']['score']))
            print("Malicious         :", str(final_response['verdicts']['overall']['malicious']))
            print("Screenshot of URL :", str(final_response['task']['screenshotURL']))
            print("URLSCAN Score     :", str(final_response['verdicts']['urlscan']['score']))
            if final_response['verdicts']['urlscan']['categories']:
                print("Categories: ")
                for line in final_response['verdicts']['urlscan']['categories']:
                    print("\t"+ str(line))
            print("URLSCAN Report Reference :", str(final_response['task']['reportURL']))
    except:
        print("An Error has occured, the domain could not be resolved and scanned by URL SCAN due to restrictions")
    menu()

def url_reputation_check():
    url = str(input("Enter the URL to check for its reputation :")).strip()
    reputation_check.check_url_reputation(url)
    menu()