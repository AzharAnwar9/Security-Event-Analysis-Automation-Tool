from ipwhois import IPWhois
import json
import re
import requests
from spyse import Client
import time

def input_validate():
    print("\n")
    print("-----------------")
    print("REPUTATION CHECK")
    print("-----------------")

    userinput = input("Enter IP Address, Domain, URL or File Hash: ").split()
    ipregex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    domainregex = "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$"
    hashregex = "^[a-fA-F0-9]+$"
    #print(userinput)
    if (re.search(ipregex, userinput[0])):
        check_ip_reputation(userinput[0])
    if (re.search(":\/\/", userinput[0])):
        check_url_reputation(userinput[0])
    if (re.search(domainregex, userinput[0])):
        check_url_reputation(userinput[0])
    if (re.search(hashregex, userinput[0])):
        check_hash_reputation(userinput[0])

def check_ip_reputation(ip):
    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = "3cb220cf0cf505870a3807b154676b59e35d53f49289b3a3f65c71bba4a9d324"
    try:
        response = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip, headers={'x-apikey': '%s' % vtapikey})
        result = response.json()
        res_str = json.dumps(result)
        resp = json.loads(res_str)
        reference = "https://www.virustotal.com/gui/ip-address/"+ip
        print("IP Address                  :", ip)
        print("IP Address Owner            :", str(resp['data']['attributes']['as_owner']))
        print("Number of scan attempted    :", str(resp['data']['attributes']['last_analysis_stats']))
        print("Reputation                  :", str(resp['data']['attributes']['reputation']))
        print("\nNumber of Reportings      :", (int(resp['data']['attributes']['last_analysis_stats']['malicious']) + int(resp['data']['attributes']['last_analysis_stats']['suspicious'])))
        print("Virustotal report reference :", reference)
    except:
        print("IP not found or wrong input")

    print("\n")
    print("-----------------")
    print("ABUSEIPDB REPORT")
    print("-----------------")

    ABIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'
    days = '180'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': days
    }
    headers = {
        'Accept': 'application/json',
        'Key': 'a9858b6d250e5ef3000e5326615e83a823843f7352afe9a4c59d4bb64e515e31fd795e6858c7dc1c'
    }
    reference = "https://www.abuseipdb.com/check/"+ip

    try:
        response = requests.request(method='GET', url=ABIPDB_URL, headers=headers, params=querystring)
        result = response.json()
        print("\nIP Address      :" + str(result['data']['ipAddress']))
        print("Number of Reports :" + str(result['data']['totalReports']))
        print("Abuse Score       :" + str(result['data']['abuseConfidenceScore']) + "%")
        print("Last Reported on  :" + str(result['data']['lastReportedAt']))
        print("Report Reference  :" + reference)        
    except:
        print("IP not found")

    print("\n")
    print("------------")
    print("SPYSE REPORT")
    print("------------")
    
    client = Client("44801a9c-61b5-41be-a005-7b283bb3e2a1")
    reference = "https://spyse.com/search?query=%s&target=ip"%ip

    try:
        ip_details = client.get_ip_details(ip)
        print("\nIP Address           :", str(ip_details.ip))
        print("Severity out of 100    :", str(ip_details.abuses.score))
        print("Is the IP dangerous    :", str(ip_details.security_score.score))
        print("CVE List               :", str(ip_details.cve_list))
        print("Spyse Report Reference :", reference)
    except:
        print("IP not found")

    try:
        obj = IPWhois(ip)
        res = obj.lookup_whois()
        addr = str(res['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n")
        print("------------")
        print("WHOIS RECORD")
        print("------------")
        print("CIDR    :" + str(res['nets'][0]['cidr']))
        print("Name    :" + str(res['nets'][0]['name']))
        print("Range   :" + str(res['nets'][0]['range']))
        print("Descr   :" + str(res['nets'][0]['description']))
        print("Country :" + str(res['nets'][0]['country']))
        print("Address :" + addr)
        print("Created :" + str(res['nets'][0]['created']))
        print("Updated :" + str(res['nets'][0]['updated']))
    except:
        print("Invalid or Private IP Address")

    print("\n\n")
    ret = int(input("Enter 1 to return to menu"))
    if ret == 1:
        return
    else:
        print("Wrong input, returing anyways")
        return

def check_url_reputation(url):
    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = "3cb220cf0cf505870a3807b154676b59e35d53f49289b3a3f65c71bba4a9d324"
    try:
        baseurl = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {'apikey': vtapikey, 'resource': url }
        response = requests.get(baseurl, params=params)
        result = response.json()
        res_str = json.dumps(result)
        resp = json.loads(res_str)
        
        #print(resp) # VIRUSTOTAL IS NOT A GREAT RESOURCE FOR URL REPUTATION however v2 works fine 
        print("URL Submitted               :", str(resp['url']))
        print("Number of scan attempted    :", str(resp['total']))
        print("Number of Reportings        :", str(resp['positives']))
        print("Virustotal report reference :", str(resp['permalink']))
    except:
        print("URL not found or wrong input")

    print("\n")
    print("------------------")
    print("URL SCAN IO REPORT")
    print("------------------")
    
    urlscanapikey = "0f2749ad-af19-4cf2-b73a-5e627756ae14"
    scan_type = 'private'
    type = str(input('''Do you want to run a public scan?[y/N]
    A public scan result will be available in URL SCAN IO DB and searchable on open internet.
    Default is private.'''))

    if type == 'y':
        scan_type = 'public'
    
    headers = {'Content-Type': 'application/json','API-Key': urlscanapikey,}
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

    print("\n\n")
    ret = int(input("Enter 1 to return to menu"))
    if ret == 1:
        return
    else:
        print("Wrong input, returing anyways")
        return

def check_hash_reputation(hash):
    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = "3cb220cf0cf505870a3807b154676b59e35d53f49289b3a3f65c71bba4a9d324"
    try:
        response = requests.get("https://www.virustotal.com/api/v3/files/%s" % hash, headers={'x-apikey': '%s' %vtapikey}).json()
        res_str = json.dumps(response)
        resp = json.loads(res_str)
        reference = "https://www.virustotal.com/gui/file/"+hash
        print("Hash Submitted       :", hash)
        print("File Signature       :", str(resp['data']['attributes']['signature_info']))
        print("File Type            :", str(resp['data']['attributes']['type_description']))
        print("Total Detection      :", str(resp['data']['attributes']['last_analysis_stats']))
        print("Threat Label         :", str(resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))
        print("Virustotal Reference :", reference)
    except:
        print("File not found or wrong input")

    print("\n\n")
    ret = int(input("Enter 1 to return to menu"))
    if ret == 1:
        return
    else:
        print("Wrong input, returing anyways")
        return