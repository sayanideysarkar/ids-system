# ids-system
# Chapter 1: Introduction
In an era defined by digital transformation and interconnectedness, the paramount
importance of network security is undeniable. Malicious actors are developing
increasingly sophisticated malicious software and tools in order to exploit existing
system vulnerabilities. We require a robust cybersecurity system to defend against
cyberattacks and intrusions.
# 1.1 Overview
The subsequent segments of this report delve into the specifics of each aspect. It
provides a comprehensive literature review that lays the groundwork for
comprehending the significance of intrusion detection, vulnerability assessment, and
log management.
# 1.2 Background and Context
As organizations heavily depend on digital infrastructure, the risk of cyber threats
looms larger than ever. In the age of network security, Intrusion Detection Systems
(IDS) play a vital role by effectively detecting and promptly addressing incidents of
unauthorized access, anomalies, and malicious actions. Additionally, Vulnerability
Assessment Tools like Nessus help in the identification of vulnerabilities and
weaknesses of a system or network.
# 1.3 Research Objectives
Nessus used to perform vulnerability scanning of systems and networks, identifying
weaknesses and flaws that could be exploited by attackers.The main purpose of IDS
to identify intrusions in a network or system. It detects any unauthorized or malicious
activity .Used Splunk’s powerful analytics engine to detect complex security incidents,
correlate disparate events, and provide actionable insights for rapid incident
response.
# 1.4 Significance of the Study
Integrating Snort, Nessus, and Splunk provides a multidimensional approach to
network security. In addition, the study explores the ethical dimensions of network
security automation, which reflects the broader societal and technological
innovations.
# 1.5 Scope and Limitations
The research is conducted in a controlled environment using Kali Linux and Ubuntu
to simulate real-world network interactions and potential attacks. While the integration
# 2.1 Intrusion Detection Systems (IDS): A Foundation in Cybersecurity
# INTRUSION DETECTION SYSTEM
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
# 2.2 Vulnerability Scanners and Nessus: Navigating Digital weaknesses
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
# 2.3 Splunk: Illuminating Insights through Data Analytics:
# Introduction to Splunk:
Splunk is a powerful log management and data analysis platform used widely in
cybersecurity, IT operations, and DevOps. It helps collect, index, search, analyze, and
visualize machine-generated data in real time.
# 4.2 System Architecture:  
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
<img width="1090" height="900" alt="image" src="https://github.com/user-attachments/assets/08f4945e-e5ec-410b-844b-84ef69a997a4" />

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













