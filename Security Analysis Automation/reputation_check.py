import base64
import config
from ipwhois import IPWhois
import json
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import re
import requests
from spyse import Client
import time
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

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

    vtapikey = config.key_dictionary['VirusTotal API Key']
    try:
        response = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" % ip, headers={'x-apikey': '%s' % vtapikey})
        result = response.json()
        res_str = json.dumps(result)
        resp = json.loads(res_str)
        reference = "https://www.virustotal.com/gui/ip-address/"+ip
        print("IP Address                  :", ip)
        if 'as_owner' in resp['data']['attributes']:
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
        'Key': config.key_dictionary['Abuse IP DB API Key']
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
    print("---------------------")
    print("AlienVault OTX REPORT")
    print("---------------------")
    
    try:
        BASE_URL = 'https://otx.alienvault.com:443/api/v1/'
        API_KEY = config.key_dictionary['AlienVault OTX API Key']
        url = 'indicators/IPv4/'
        #section = ''
        headers = {
            'accept': 'application/json',
            'X-OTX-API-KEY': API_KEY,
        }

        reference = "https://otx.alienvault.com/indicator/ip/" + ip
        response = requests.get(BASE_URL + url + ip + '/', headers=headers)
        resp = response.json()
        print("IP Address      :", resp['indicator'])
        print("IP Address Type :", resp['type'])
        print("IP Owner/ASN    :", resp['asn'])
        print("City            :", resp['city'])
        print("Country         :", resp['country_name'])
        tags = dict()
        for i in range(0,resp['pulse_info']['count']) :
            for l in resp['pulse_info']['pulses'][i]['tags'] :
                tags[l] = tags.get(l, 0) + 1
        print("Tags            :", tags)
        print("Reference       :", reference)
    except:
        print("IP Not Found on AlientVault OTX searches")

    print("\n")
    print("------------")
    print("SPYSE REPORT")
    print("------------")
    
    client = Client(config.key_dictionary['Spyse API Key'])
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

    vtapikey = config.key_dictionary['VirusTotal API Key']
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

        res = list(resp['scans'].values())
        tags = dict()
        for i in range(0, len(res)):
            tags[str(res[i]['result'])] = tags.get(str(res[i]['result']), 0) + 1
        print("Tags                        :", tags)
    except:
        print("URL not found or wrong input")

    print("\n")
    print("-----------------------")
    print("AlienVault OTXv2 REPORT")
    print("-----------------------")

    try:
        otx = OTXv2(config.key_dictionary['AlienVault OTX API Key'])
        final_domain = urlparse(url).netloc
        results = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, final_domain)
        print("URL                         :", results['general']['indicator'])
        print("Type                        :", results['general']['type_title'])
        print("Number of Detections/Pulses :", results['general']['pulse_info']['count'])
        #print(results['geo']['asn'])
        # #print(results['geo']['country_name'])
        print("Possible Malware Detection  :", len(results['malware']['data']))
        print("URL Lists Counts            :", len(results['url_list']['url_list']))
        #print(results)
        tags = list()
        for i in range(0, len(results['general']['validation'])) :
            tags.append(results['general']['validation'][i]['name'])    
        length_of_validation = len(tuple(tags))
        if length_of_validation > 0 :
            print("Validation tags             :", tuple(tags))
        else :
            print("Validtion tags              : Suspicious as the URL/Domain is not listed on Major SEs")
    except:
        print("URL Not Found on AlientVault OTX searches")

    print("\n")
    print("----------------")
    print("Phishtank Report")
    print("----------------")

    try :
        headers = {
            'format': 'json'
        }

        BASE_URL = "http://checkurl.phishtank.com/checkurl/"
        new_check_bytes = url.encode()
        base64_bytes = base64.b64encode(new_check_bytes)
        base64_new_check = base64_bytes.decode('ascii')
        BASE_URL += base64_new_check
        response = requests.request("POST", url=BASE_URL, headers=headers)
        #print(response.text)
        root = ET.fromstring(response.text)
        print("Submitted URL     :", root[1][0][0].text)
        print("Found in Database :", root[1][0][1].text)
        print("Phish ID          :", root[1][0][2].text)
        print("Reference         :", root[1][0][3].text)
        print("Verified          :", root[1][0][4].text)
        if root[1][0][4].text == 'true' :
            print("Verification Date :", root[1][0][5].text)
            print("is still Valid    :", root[1][0][6].text)
    except:
        print("The URL is not listed for Phishing in Phishtank's DB")

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
    print("-----------------------")
    print("AlienVault OTXv2 REPORT")
    print("-----------------------")
    reference = "https://otx.alienvault.com/indicator/file/" + hash
    try:
        BASE_URL = 'https://otx.alienvault.com:443/api/v1/'
        API_KEY = config.key_dictionary['AlienVault OTX API Key']
        url = 'indicators/file/'
        section = 'analysis'
        headers = {
            'accept': 'application/json',
            'X-OTX-API-KEY': API_KEY,
        }
        
        reference = "https://otx.alienvault.com/indicator/file/" + hash
        response = requests.get(BASE_URL + url + hash + '/' + section, headers=headers)
        resp = response.json()
        #print(resp)
        print("Hash                 :", hash)
        print("File Type            :", resp['analysis']['info']['results']['file_type'])
        print("Cuckoo Sandbox Score :", resp['analysis']['plugins']['cuckoo']['result']['info']['combined_score'])
        print("Number of Signatures :", len(resp['analysis']['plugins']['cuckoo']['result']['signatures']))
        print("MS-Defender Results  :", resp['analysis']['plugins']['msdefender']['results'])
        print("Avast AV Results     :", resp['analysis']['plugins']['avast']['results'])
        print("Original File Name (Exif Tool) :", resp['analysis']['plugins']['exiftool']['results']['EXE:OriginalFileName'])
        print("Product Name         :", resp['analysis']['plugins']['exiftool']['results']['EXE:ProductName'])
        print("File Platform        :", resp['analysis']['plugins']['exiftool']['results']['EXE:FileOS'])
    except:
        print("Complete Details were not fetched, please visit below reference through browser for more details if any.")
        print("Reference            :", reference)

    print("\n")
    print("-----------------")
    print("VIRUSTOTAL REPORT")
    print("-----------------")

    vtapikey = config.key_dictionary['VirusTotal API Key']
    try:
        response = requests.get("https://www.virustotal.com/api/v3/files/%s" % hash, headers={'x-apikey': '%s' %vtapikey}).json()
        res_str = json.dumps(response)
        resp = json.loads(res_str)
        #print(resp)
        reference = "https://www.virustotal.com/gui/file/"+hash

        no_of_reporting = int(resp['data']['attributes']['last_analysis_stats']['malicious']) + int(resp['data']['attributes']['last_analysis_stats']['suspicious'])
        print("Hash Submitted       :", hash)
        print("File Type            :", str(resp['data']['attributes']['type_description']))
        print("Total Detection      :", str(resp['data']['attributes']['last_analysis_stats']))
        print("Number of Reportings :", no_of_reporting)
        if 'signature_info' in resp['data']['attributes']:
            print("File Signature       :", str(resp['data']['attributes']['signature_info']))
        if 'popular_threat_classification' in resp['data']['attributes']:
            print("Threat Label         :", str(resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))
        print("Virustotal Reference :", reference)
    except:
        print("completed!")

    print("\n")
    ret = int(input("Enter 1 to return to menu"))
    if ret == 1:
        return
    else:
        print("Wrong input, returing anyways")
        return
