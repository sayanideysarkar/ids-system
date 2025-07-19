# ids-system
# Introduction
In an era defined by digital transformation and interconnectedness, the paramount
importance of network security is undeniable. Malicious actors are developing
increasingly sophisticated malicious software and tools in order to exploit existing
system vulnerabilities. We require a robust cybersecurity system to defend against
cyberattacks and intrusions.

# Intrusion Detection Systems (IDS): A Foundation in Cybersecurity
An Intrusion Detection System (IDS) is a cybersecurity solution designed to monitor
network or system activities for malicious actions, policy violations, or abnormal
behaviour. It is a foundational component of any security architecture aimed at
detecting threats before they cause harm.
# Types of IDS:
# 1. Network-based IDS (NID) 
Monitors traffic across a network segment. Typically
located at key network points like gateways, routers, or switches. Detects suspicious
patterns in packet flows, such as port scans, DDoS attacks, or malware
communication. Example tools: Snort, Suricata, Zeek (formerly Bro).
# 2. Host-based IDS (HIDS) 
Runs on individual hosts (devices) to monitor internal
activity. Tracks file integrity, logins/logouts, configuration changes, and system calls.
Excellent for detecting insider threats and malware that may not be visible on the
network. Example tools: OSSEC, Tripwire, AIDE.
# Detection Methods of IDS:
# 1. Signature-Based Detection (Pattern Matching) 
Compares incoming data to a
database of known threat signatures (attack patterns). Best at detecting known threats
like malware, exploits, and known attack vectors.
# 2. Anomaly-Based Detection 
Establishes a baseline of normal behaviour (e.g.,
traffic volume, login patterns). Flags deviations from this baseline as potential threats.
Best at detecting: Unknown or novel attacks that don’t match any known signature.
# UNVEILING SNORT: UNITING POWER AND FLEXIBILITY
Snort is an open-source intrusion detection and prevention system pioneer. Martin
Roesch's innovative thinking was critical in the late 1990s creation of Snort, and its
adaptability and open-source nature influenced the cybersecurity domain. The
capacity to detect a wide range of network-based threats and vulnerabilities is its key
advantage.
# The Power and Versatility of Snort:
Snort is a landmark among Intrusion Detection and Prevention Systems (IDS/IPS)
due to its attractive blend of power and versatility. Snort's open-source nature provides
organizations with the unique opportunity to precisely adjust its capabilities to their
needs, ensuring a responsive defense against the ever-changing cyber world.
The global cybersecurity community collaborated to create the symphony of Snort's
capabilities, which resonates across its large rule library. This repository contains a
wide range of prebuilt rules, each designed to identify different forms of attacks. These
guidelines, when combined, build a strong defense that adjusts to new threats.
Snort's canvas, on the other hand, goes beyond the predefined. Organizations can
develop customized rules to improve their defense methods and anticipate new attack
vectors. This customization enables organizations to remain adaptable and proactive
in dealing with cyber threats.
# Vulnerability Scanners and Nessus: Navigating Digital weaknesses
To address the potential threat of unauthorized access by fraudulent individuals to
digital systems, apps, and networks, it is imperative to employ vulnerability scanners.
Instances of vulnerabilities encompass unsecured configurations, obsolete software,
and unpatched issues about operating systems and applications.
Various forms of vulnerability scanning, such as active and passive monitoring, serve
to fulfill this pivotal function. Active scanning is a technique employed to identify
vulnerabilities by rapidly establishing a network connection with the designated target
system. Conversely, passive evaluations entail the analysis of network data to detect
possible vulnerabilities without causing any system interruption.
Nessus is one of the most widely used vulnerability assessment tools in cybersecurity.
Developed by Tenable, Inc., it helps organizations identify and fix security
vulnerabilities in their IT infrastructure before they can be exploited.
# Splunk: Illuminating Insights through Data Analytics:
Splunk is a powerful log management and data analysis platform used widely in
cybersecurity, IT operations, and DevOps. It helps collect, index, search, analyze, and
visualize machine-generated data in real time.
# System Architecture:  
<img width="1090" height="415" alt="image" src="https://github.com/user-attachments/assets/19def4de-1847-48ed-b8b8-e4828834e247" />
 <img width="1090" height="453" alt="image" src="https://github.com/user-attachments/assets/cf7daedd-9fe9-41e8-9b0c-3f8e791f89a1" />

# SNORT SETUP AND CONFIGURATION
# STEP 1

In this process we are using ubuntu and installing snort. Before installing snort,
we have to update this interface and install it using command in terminal.
Sudo apt-get update → for update,
Sudo apt-get install snort-y → for installing snort.

<img width="1090" height="556" alt="image" src="https://github.com/user-attachments/assets/5ebb5fca-94e6-4832-9331-3cb0c8b99e45" />
<img width="1090" height="484" alt="image" src="https://github.com/user-attachments/assets/733a31da-ce60-44a0-b6c1-82823c53a4da" />

# STEP 2

While installing snort it requires host machine Ip address. So, we find this IP address and past it in prompt. 

<img width="1090" height="900" alt="image" src="https://github.com/user-attachments/assets/cb2c0e86-af02-4c68-a2ce-16f736a0ca8d" />

# STEP 3

Now we have to open the config file of snort using any editor. Here we using gedit. 
The command is sudo gedit /etc/snort/snort.conf 

<img width="1090" height="510" alt="image" src="https://github.com/user-attachments/assets/f237215e-66ec-42c2-81ac-583d551f10ab" />

# STEP 4

Here in this config file, we have to change HOME_NET to host ip address. 

<img width="1090" height="370" alt="image" src="https://github.com/user-attachments/assets/e480d01b-03dc-47cf-a5cf-743f3cd0f604" />

# STEP 5

Save it and close the editor. 
Now we have to make some rules in snort local rules file. Here if we make the rules then we can get proper tracking of trespassing activities. 
The command is → sudo gedit /etc/snort/rules/local.rules 
We can make various types of rules using online website such as snorpy. 

<img width="1090" height="698" alt="image" src="https://github.com/user-attachments/assets/01b24d29-efcd-4ead-baa3-c28751158373" />

# STEP 6

Here are some rules and its application. 
Icmp → alert icmp any any -> &HOME_NET any (msg:”ICMP Ping Detected”; sid : 10001; 
rev:1;) 
Tcp → alert tcp any any -> &HOME_NET  22 (msg:”SSH Authentication Attempt”; sid : 10001; rev:1;) 

<img width="1090" height="723" alt="image" src="https://github.com/user-attachments/assets/b08d2ab4-77e9-4cce-864e-6221b29e572c" />

# STEP 7

Now we run this snort using a command. 

<img width="1090" height="135" alt="image" src="https://github.com/user-attachments/assets/50bea7b8-1179-4fd3-bccd-4476f2257e2f" />

# STEP 8

After running this command if we try to access this host ip address from another device we can see the access log file. 

<img width="1090" height="448" alt="image" src="https://github.com/user-attachments/assets/d5eacdda-1e5b-4a61-85e7-58fc342dd94a" />

# STEP 9

This is from another machine where we using ping command to check the host IP Address. 

<img width="1090" height="390" alt="image" src="https://github.com/user-attachments/assets/d9462d37-e9a1-4136-ac50-62552b0f089c" />

It is from host snort console where we can see the access log. 

# SPLUNK SETUP AND CONFIGURATION IN AWS CLOUD
# STEP 1

STEP 1: Sign in to the AWS Management Console → Go to:
https://console.aws.amazon.com → After that you will be redirect this page.

<img width="1090" height="502" alt="image" src="https://github.com/user-attachments/assets/e7c6b2a3-57e0-4e5c-92f7-b8bc5e02fae3" />

# STEP 2

 Navigate to the VPC Dashboard → You can search for "VPC" in the search bar at the top. 

 <img width="1090" height="474" alt="image" src="https://github.com/user-attachments/assets/4b883445-72c6-443a-acdb-1e5cdad79ec8" />

 # STEP 3

 Open the VPC Creation Wizard → Click on "Create VPC" 

 <img width="1090" height="351" alt="image" src="https://github.com/user-attachments/assets/edf9cc5e-9778-4c48-a91f-5be742d8bd98" />

 # STEP 4

  Choose "VPC only" (not "VPC and more") to avoid configuring subnets or other resources → Configure VPC Settings → Name tag →IPv4 CIDR block →  IPv6 CIDR block → Tenancy: 

  <img width="1090" height="499" alt="image" src="https://github.com/user-attachments/assets/bbbe52c7-f623-4219-9c72-6588cb454686" />

 # STEP 5

 Click Create VPC → AWS will take a few seconds to create the VPC → You'll see a success message with the new VPC ID. 

 <img width="1090" height="201" alt="image" src="https://github.com/user-attachments/assets/d71839f8-5d8f-4ad8-ab07-f460bd9a1b5d" />

 # STEP 6

 You'll see a success message with the new VPC ID.

 <img width="1090" height="518" alt="image" src="https://github.com/user-attachments/assets/bcec1724-387c-46d4-a508-a651bab7afd4" />

 # STEP 7

 Verify VPC Creation → Return to the Your VPCs section in the VPC Dashboard → Confirm that your VPC is listed and shows the correct CIDR block. 

 <img width="1090" height="518" alt="image" src="https://github.com/user-attachments/assets/ba624dbc-2baf-4350-9ce6-5a055005a834" />

 # STEP 8

 Navigate to the VPC Dashboard → Subnets → Click Create subnet. 

 <img width="1090" height="231" alt="image" src="https://github.com/user-attachments/assets/72e1b648-98d0-4f8a-bbf8-49e724ab33e0" />

 # STEP 9

 Choose your VPC: Select the VPC you just created. 

 <img width="1090" height="501" alt="image" src="https://github.com/user-attachments/assets/540d427c-8c10-41c1-8d56-9afc2210a62c" />

 # STEP 10

 Subnet settings → Name tag → Availability Zone → IPv4 CIDR block (Optional) →  Add more subnets for different AZs or purposes (e.g., private/public).

 <img width="1090" height="518" alt="image" src="https://github.com/user-attachments/assets/b32a440f-afa2-4bc9-8b72-bd4eaeaac654" />

 # STEP 11

 <img width="1090" height="226" alt="image" src="https://github.com/user-attachments/assets/12309bdd-399e-4d86-9f88-405496cd82bd" />

 # STEP 12

 You can see subnet is successfully created.

 <img width="1090" height="544" alt="image" src="https://github.com/user-attachments/assets/93127ea1-1bd6-4517-8281-125755755a0d" />

 # STEP 13

 Now you need to Launch Instance. 

 <img width="1090" height="480" alt="image" src="https://github.com/user-attachments/assets/629110cf-a93a-4841-b109-0c760ee9ec7a" />

 # STEP 14

 Configuration you Instance. 

 <img width="1090" height="501" alt="image" src="https://github.com/user-attachments/assets/d5bf022e-20a3-4ffc-ac39-339881c8577d" />

 # STEP 15

 Create new key pair  

 <img width="1090" height="424" alt="image" src="https://github.com/user-attachments/assets/579fadff-038b-49de-b7c1-13552a36b5c8" />

 # STEP 16

  After creating key pair, complete rest of the configuration like network settings, Rules, Storage etc. 

  <img width="1090" height="448" alt="image" src="https://github.com/user-attachments/assets/43d6c98a-f90f-4936-adde-e39068fa38d5" />
  <img width="1090" height="514" alt="image" src="https://github.com/user-attachments/assets/523dd130-72ed-424e-abc5-0e0a9de662df" />
  <img width="1090" height="415" alt="image" src="https://github.com/user-attachments/assets/d661553c-b430-4450-9138-e9ef08cab110" />
  <img width="1090" height="475" alt="image" src="https://github.com/user-attachments/assets/33dad48d-d01b-4e16-be8c-f52144e61b15" />

 # STEP 17

 Click on Launch Instance. After creating Instance → Click on Instance → Networking → manage IP Address.

 <img width="1090" height="480" alt="image" src="https://github.com/user-attachments/assets/c152ebc4-2257-4882-a11b-69c4aaef3ab0" />

 # STEP 18

 To assign a persistent public IPv4 address → Click the blue underlined text that says "allocate Elastic IP addresses". This will likely open a new tab or window where you can allocate an Elastic IP address in your AWS account. 

 <img width="1090" height="339" alt="image" src="https://github.com/user-attachments/assets/742356ff-02f1-4083-98e0-84e625b1e5db" />

 # STEP 19

 You can see the page now. 

 <img width="1090" height="413" alt="image" src="https://github.com/user-attachments/assets/566fc03c-3db9-4479-b19f-a2b41becbada" />

 # STEP 20

 Choose the Public IPv4 address pool → Choose the Network border group → Add tags → Allocate the Elastic IP address → click the Allocate button in the bottom right corner of the page. 

 <img width="1090" height="475" alt="image" src="https://github.com/user-attachments/assets/9183eee6-dea5-4ba6-88a0-98835cf31916" />

 # STEP 21
 
 You can see Elastic IP allocated successfully. 

 <img width="1090" height="454" alt="image" src="https://github.com/user-attachments/assets/417ccc93-bcc8-414d-a680-3f2289203220" />

 # STEP 22

 After clicking Allocate, AWS will provision a new Elastic IP address for your account in the selected region. You will then need to associate this Elastic IP address with your EC2 instance's network interface. 

 <img width="1090" height="613" alt="image" src="https://github.com/user-attachments/assets/28b09aa9-b3a5-4f1f-ab2e-79ac521f1952" />

 # STEP 23

 Based on the "Instances" page and the details shown for the selected instance. 

 <img width="1090" height="613" alt="image" src="https://github.com/user-attachments/assets/c1faa224-d4fc-44da-bdca-95923829dc1d" />

 # STEP 24

 To connect to the instance → Select the instance by checking the box next to its name ("Splunk Server"). → Click on Connect → This will provide you with different options to connect to your instance (e.g., using EC2 Instance Connect, Session Manager, or SSH). 
Follow the instructions provided for your chosen method. 

<img width="1090" height="521" alt="image" src="https://github.com/user-attachments/assets/ceaf8a1d-382c-402f-99ce-42a9666b88a4" />

# STEP 25

Here you can see the instance is launched. 

<img width="1090" height="481" alt="image" src="https://github.com/user-attachments/assets/88850cc2-ea0d-40b5-930a-acfbb1d83381" />

# STEP 26

For installation of Splunk → Go to the Splunk website → Create account. 

<img width="1090" height="456" alt="image" src="https://github.com/user-attachments/assets/db31ba9b-c8da-4793-a13c-67324e0a6160" />

# STEP 27

Downloaded Splunk Enterprise Package: You need to download the appropriate .rpm (for Red Hat, CentOS, Fedora), .deb (for Debian, Ubuntu), 

<img width="1090" height="587" alt="image" src="https://github.com/user-attachments/assets/6ad57587-ffe4-48f0-bd19-c879f261c914" />

# STEP 28

Now run this command after copy the download link. 

<img width="1090" height="474" alt="image" src="https://github.com/user-attachments/assets/84d72c12-64e6-4aa6-91eb-382d82cf9ee0" />

# STEP 29

NoW depackage the file by these commands. 

<img width="1090" height="314" alt="image" src="https://github.com/user-attachments/assets/dffe005b-9085-4244-8067-eb2bf14fdbdc" />

# STEP 30

Start the splunk. 

<img width="1090" height="480" alt="image" src="https://github.com/user-attachments/assets/04c68405-59a7-4f27-af0c-66c4eba0b5b4" />

# STEP 31

Accept the license.

<img width="1090" height="431" alt="image" src="https://github.com/user-attachments/assets/772ceb61-9896-4244-bec0-a13210c12c7d" />

# STEP 32 

The installation is complete. 

<img width="1090" height="494" alt="image" src="https://github.com/user-attachments/assets/48332523-ba3b-4b81-93e1-90e017f0814b" />

# STEP 33

After creating Password → Login to this page.

<img width="1090" height="385" alt="image" src="https://github.com/user-attachments/assets/045c86b6-81e9-44ee-b6b4-3df923f68f89" />

# STEP 34

 For checking the status run this command.

 <img width="1090" height="476" alt="image" src="https://github.com/user-attachments/assets/4a20a5a3-043d-4aee-a1f2-61858aa68127" />

 # STEP 35

 You will be redirecting this page.

 <img width="1090" height="545" alt="image" src="https://github.com/user-attachments/assets/3c0fa50c-da94-4269-b0d1-4daf5482d1c4" />

 # STEP 36

 Go to the forwarding and receiving. 

 <img width="1090" height="451" alt="image" src="https://github.com/user-attachments/assets/9db1af09-3673-4f10-b046-3c87f747263e" />

 # STEP 37

 Configure this → click on configure receiving.

 <img width="1090" height="237" alt="image" src="https://github.com/user-attachments/assets/83483df0-fa62-4214-9de3-7e15d85528cd" />
<img width="1090" height="363" alt="image" src="https://github.com/user-attachments/assets/96f26f69-0b43-48a6-84c6-c0b1e6050e30" />

 # STEP 38

 Add new receiving port. 

 <img width="1090" height="289" alt="image" src="https://github.com/user-attachments/assets/97769309-e977-4e54-8e88-3ff2fff71783" />

 # STEP 39

 Go to Home → Manage Apps  

 <img width="1090" height="230" alt="image" src="https://github.com/user-attachments/assets/503320fc-fe10-42c9-b6e8-95e962671cd0" />

 # STEP 40
 
 Search for snort → Install Snort 

 <img width="1090" height="358" alt="image" src="https://github.com/user-attachments/assets/14c22a8c-e712-4978-8dd7-1d3be5c8d762" />

 # STEP 41

 Login with Splunk username and password and install the snort. 

 <img width="1090" height="503" alt="image" src="https://github.com/user-attachments/assets/db94e49a-c64d-4d4b-b7e6-a958a11b2b49" />
 <img width="1090" height="243" alt="image" src="https://github.com/user-attachments/assets/fe2b5e4f-c316-418a-8896-0e442148ab0e" />

 # STEP 42

 Here you can see all the result 

 <img width="1090" height="564" alt="image" src="https://github.com/user-attachments/assets/2c30c163-9f3e-40eb-b557-aa9d6f3a675d" />

 You can also see → 
1.	Top 10 Classifications  
2.	Snort Event Types  
3.	Sources and Signatures  
4.	Last 100 events 

<img width="1090" height="548" alt="image" src="https://github.com/user-attachments/assets/d0ef1c8f-d651-4b96-8592-e19c7bcf14c0" />

If you want then you can generate report according to your requirement like this way. 

<img width="1090" height="243" alt="image" src="https://github.com/user-attachments/assets/ea37efbe-4893-40fa-a81e-39f98cf73a68" />

These are my Splunk report. 

<img width="1090" height="626" alt="image" src="https://github.com/user-attachments/assets/196532a1-404f-484a-84cb-c2ead5333b6a" />
































 















  






















