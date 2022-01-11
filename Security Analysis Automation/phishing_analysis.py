import config
import email
from emailrep import EmailRep
import file_sandbox
from PIL import Image
import reputation_check
import tkinter
from tkinter import filedialog
import webbrowser

def menu():
    print("\n")
    print("----------------------------------------")
    print("Email Security (Phishing Email Analysis)")
    print("----------------------------------------")

    print("\nPlease select an option from below : ")
    print("OPTION 1: Email Address Verification")
    print("OPTION 2: Analyze a Phishing Site")
    print("OPTION 3: Sandbox an Email Attachment")
    print("OPTION 4: Email Header Analysis")
    print("OPTION 5: General GUidelines for Identification of Phishing Attack")
    print("OPTION 0: Exit")
    phishing_analysis_menu(int(input()))

def phishing_analysis_menu(selected_option):
    
    if selected_option == 1 :
        email_address_validation()
    elif selected_option == 2 :
        phishing_site()
    elif selected_option == 3 :
        attachment_sandbox()
    elif selected_option == 4 :
        header_analysis()
    elif selected_option == 5 :
        guidelines()
    elif selected_option == 0 :
        return
    else :
        print("Incorrect input")
        menu()

def email_address_validation():
    email_address = str(input("Enter Email Address to check :").strip())
    print("\n")
    print("-----------------------")
    print("Email Reputation REPORT")
    print("-----------------------")
    try:
        # setup your api key (optional)
        emailrep = EmailRep(config.key_dictionary['Email Reputation IO API Key'])
        # query an email address
        results = emailrep.query(email_address)
        print("Submitted Email           :", results['email'])
        print("Email Reputation          :", results['reputation'])
        print("Is Email Suspicious       :", results['suspicious'])
        print("Is Email Blacklisted      :", results['details']['blacklisted'])
        print("Recent Malicious Activity :", results['details']['malicious_activity_recent'])
        print("Credential Leak           :", results['details']['credentials_leaked'])
        print("Recent Credential Leak    :", results['details']['credentials_leaked_recent'])
        print("Found in Data Breach      :", results['details']['data_breach'])
        print("Domain Reputation         :", results['details']['domain_reputation'])
        print("Number of Days since Domain Creation :", results['details']['days_since_domain_creation'])
        print("Spam Reputation           :", results['details']['spam'])
        print("is Domain Spoofable       :", results['details']['spoofable'])
        print("Profiles                  :", results['details']['profiles'])
        print("Summary :\n", results['summary'])
    except:
        print("Email Not Found")
    menu()

def phishing_site():
    url = str(input("Enter URL to check :").strip())
    reputation_check.check_url_reputation(url)
    menu()

def attachment_sandbox():
    file_sandbox.file_sandbox()
    menu()

def header_analysis():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(title="Select Message File(.eml)")
    f = open(root.filename)
    msg = email.message_from_file(f)
    f.close()
    parser = email.parser.HeaderParser()
    headers = parser.parsestr(msg.as_string())
    for h in headers.items():
        print(h)
    root.destroy()
    menu()

def guidelines():
    webbrowser.open(r'Phishing_Identification.png')
    menu()
