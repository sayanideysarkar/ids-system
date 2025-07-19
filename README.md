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

# SNORT SETUP AND CONFIGURATION IN UBUNTU VM
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


# NESSUS SETUP AND CONFIGURATION IN KALI LINUX

# STEP 1

 In this process we are using Virtual Box and Kali Linux. Make sure both of these are installed in your laptop / pc. Also check the network adapter will be Bridged Adapter. 

 <img width="1122" height="613" alt="image" src="https://github.com/user-attachments/assets/0acd1391-b4dc-46fd-8500-d92a9ad962bf" />

 # STEP 2
 
 You can see Kali Linux is now open properly. 

 <img width="1122" height="620" alt="image" src="https://github.com/user-attachments/assets/d958d167-352c-4545-897c-c8074217ed3a" />

 # STEP 3

 Before the installation there are some things which is necessary like a good network connection, a Gmail ID, where you can get the activation key of your Nessus account. 
 After open Kali Linux → Go to Mozilla Firefox → Type “Tenable Nessus Download” → Click on the “Downloads” link. 

<img width="1122" height="624" alt="image" src="https://github.com/user-attachments/assets/1b77e523-30d1-4bbf-b46d-37ea077e0c0c" />

# STEP 4

After open you can see this type of page and click on view downloads of the first one

<img width="1122" height="629" alt="image" src="https://github.com/user-attachments/assets/847917f8-8606-47dc-85a2-bcdf680d19bd" />

# STEP 5

Now you need to configure the downloaded software → 1st Platform will be “Linux-Debian-amd64”. You can see my configuration as well. 

<img width="1122" height="596" alt="image" src="https://github.com/user-attachments/assets/cc10c15a-27ab-4878-89eb-456e782e8a0c" />

# STEP 6

 Before Click on Download → Click on “Checksum” → Copy the SHA256 Value → Paste it in your Linux Notepad for future use. 

 <img width="1122" height="597" alt="image" src="https://github.com/user-attachments/assets/dcaf7f5b-b8f1-4e70-9f7a-ee4c6440f3dc" />

 # STEP 7

 Click on Download – download will be start. 

 <img width="1122" height="236" alt="image" src="https://github.com/user-attachments/assets/33775525-52cf-49ef-9fbe-39167b7603a3" />

 # STEP 8
 
 After download this file back to your terminal and check the file is completely downloaded or not. 

 <img width="1122" height="202" alt="image" src="https://github.com/user-attachments/assets/46c63e14-27c6-4380-a609-90decf00bb56" />

 # STEP 9

 After download this file back to your terminal and complete the installation process. Now copy the checksum and the specific file and write it to another file. This file contains the checksum with the file name that we have downloaded. 

 <img width="1122" height="66" alt="image" src="https://github.com/user-attachments/assets/7193b6ea-3900-4109-90b4-1c4fbc9bd2b7" />

 # STEP 10

 To check the integrity of the file that we have downloaded enter this. 

 <img width="1033" height="275" alt="image" src="https://github.com/user-attachments/assets/50f5ee16-c7d2-48c7-964f-7d5caa00d07f" />

 # STEP 11

 Now we install the specific application on Kali Linux we have downloaded the file. 

 <img width="1122" height="286" alt="image" src="https://github.com/user-attachments/assets/68a2cffa-0317-441d-9e97-2c7907e37d67" />

 # STEP 12

 Nessus download is complete.

 <img width="1122" height="165" alt="image" src="https://github.com/user-attachments/assets/735c3dd3-57c5-4d00-99c0-551f1d6f6fbd" />

 # STEP 13
 
 After download open browser and enter “Nessus for education”. There you need to create an account and after creating account you will get an activation key. 

 <img width="1122" height="545" alt="image" src="https://github.com/user-attachments/assets/726b0022-7707-439f-affd-b146e288ed2d" />

 # STEP 14
 
 Before starting check the Nessus service status if disable then you need to start an enable the service.

 <img width="1122" height="492" alt="image" src="https://github.com/user-attachments/assets/a25c4d77-2757-4c79-94fc-00760e1175b4" />

 # STEP 15

 For starting check you’re the internet address of a network interface. 

 <img width="1122" height="256" alt="image" src="https://github.com/user-attachments/assets/c706c798-3781-40c4-aeba-cf51da5cdae6" />

 # STEP 16

 Now go to your browser and write this: https://127.0.0.1:8834 and enter. 
 After enter you will be redirecting this page.

 <img width="1122" height="435" alt="image" src="https://github.com/user-attachments/assets/dbef7253-2845-42a6-8356-e5b0b52540e7" />

 # STEP 17
 
 Mark Register Offline →Mark Nessus Expert → Click on Continue. 
 After doing this first copy the challenge code and click on Offline Registration.
 
 <img width="1122" height="439" alt="image" src="https://github.com/user-attachments/assets/f5b054a2-dd0b-4ef7-9e70-618334955b3c" />

 # STEP 18
 
 Now you need to enter the challenge code and the activation code that we have got by mail. After fill it click on Submit and you will get the license key. 

 <img width="1122" height="364" alt="image" src="https://github.com/user-attachments/assets/3388557e-e50d-4de6-89ea-27d38f86d7b2" />

 # STEP 19

 After getting the license key copy it and paste it into setup page. Click on Continue.

 <img width="1122" height="439" alt="image" src="https://github.com/user-attachments/assets/975cff39-bf96-4524-9f27-1d3757daef02" />

 # STEP 20

 Now create username and password. 

 <img width="1122" height="447" alt="image" src="https://github.com/user-attachments/assets/217d3ded-1b3e-4e8d-9fed-28f869e1c14f" />

 # STEP 21

 After initialization you can see this page. Your Installation process has completed. 

 <img width="1122" height="448" alt="image" src="https://github.com/user-attachments/assets/ae130af4-3a93-4080-826f-e4863e8dcfc4" />

 # STEP 22

 For Nessus application we need to be download some plugins. For this → Go to Settings – Software update → all → Save. 

 <img width="1122" height="364" alt="image" src="https://github.com/user-attachments/assets/fb84e842-7eb3-4361-9038-0f79d4433d58" />

 # STEP 23
 
 For manual software update → Go to Settings → Manual Software Update → Update Plugins → Continue. It will take some time. 

 <img width="1122" height="375" alt="image" src="https://github.com/user-attachments/assets/f6498ece-d11f-4711-b4b7-bcca35aefeeb" />

 STEP 24

 For starting the scan → click on New Scan → you see this interface. 
 Choose one scanning method among these. 

 <img width="1122" height="550" alt="image" src="https://github.com/user-attachments/assets/d9354ae1-f682-48a8-a6c8-671533937923" />

 # STEP 25

 We have used Splunk for log analysing. From there now we scan an IP. 
 Here we chose the “Basic Network Scan”. 

 <img width="1122" height="536" alt="image" src="https://github.com/user-attachments/assets/0155da6d-60f6-4440-adbf-9312f5579d62" />

 # STEP 26
 
 Click on that → configure all the settings → Click on Save. 

 <img width="1122" height="579" alt="image" src="https://github.com/user-attachments/assets/d28410e4-b5ee-4971-91bf-ea94b8a71672" />

 # STEP 27
 
 Now Launch the scanning process. 

 <img width="1122" height="244" alt="image" src="https://github.com/user-attachments/assets/5e58352b-6c01-4ce9-9b9c-6757fc934564" />

 #STEP 28
 
 After the scan, you will see the result of the scan. 

 <img width="1122" height="597" alt="image" src="https://github.com/user-attachments/assets/1b6dc5bf-f120-4969-822b-92ac04a0869c" />

 # STEP 29

 You can also able to know more about vulnerabilities. Just click on any one of these and you will get result. 

 <img width="1122" height="412" alt="image" src="https://github.com/user-attachments/assets/ca5612b9-3cca-4fd4-925a-46deb2f8aee1" />

 # STEP 30

 You can also generate the report of the scan in a PDF, or CSV format → Click on Report → Enter Generate report.

 <img width="1122" height="582" alt="image" src="https://github.com/user-attachments/assets/3d4123af-37fb-4e43-9d73-5009a723a514" />

 # STEP 31

 You can also see the PDF format in details. 

 <img width="1122" height="599" alt="image" src="https://github.com/user-attachments/assets/2a8f82a8-1535-4488-a60c-62e6de5f57f1" />



















 

 











































 















  






















