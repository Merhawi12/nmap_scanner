# nmap_scanner
This project is a python-base  network reconnaissance and security assessement tool that automates Nmap scanning, parses open ports and exposed service, and produces structured security outputs in JSON, CSV, and human readable report format

Target System
     ↓
Nmap Scan (subprocess)
     ↓
XML Output
     ↓
Python XML Parser
     ↓
Structured Data (Dict)
     ↓
JSON / CSV / Security Report

#Nmap Integration(Reconnaissance Layer)
The script uses Python's subprocess module to execute
nmap -sV -oX - <target>

#Why this matters
=> -sV identifies service versions, not just open port
=> XML output allows machine parsing
=> Running Nmap externally avoids reinventing scanning logic

#Security Insight
Knowing what service and which version is running helps identify:
=> Legacy services
=> Vulnerable software
=> Unnecessary exposed port

# XML Parsing & Data Extraction(Analysis Layer)
What Happens
=> Nmap’s XML output is parsed using xml.etree.ElementTree
=> Only ports in open state are extracted
=> Each service is normalized into structured data


# Multi-Format Output (Operational Layer)
JSON Output
Used for:
    SIEM ingestion
    Automation pipelines
    API integration

CSV Output
    Used for:
    Analysts
    Excel review
    Asset inventory


#Security Report Generation (Governance Layer)

Purpose
The report.txt file converts technical findings into human-readable security documentation.

Includes:
    Scan metadata (target, date)
    Open ports and services
    Security recommendations

Why This Is Important
Most security work ends in:
    Reports
    Tickets
    Risk documentation