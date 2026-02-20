# Phishing Threat Analysis & IOC Investigation Lab

## 🎯 Executive Summary

This project simulates a real-world phishing investigation from a Security Operations Center (SOC) perspective. The objective was to analyze suspicious domains, extract Indicators of Compromise (IOCs), validate malicious infrastructure, and document escalation-ready findings aligned with threat intelligence workflows.

The investigation focused on domain analysis, OSINT-based intelligence gathering, and structured IOC documentation to support incident response and defensive actions.

---

## 📖 Project Overview

This lab demonstrates practical phishing threat analysis using open-source intelligence (OSINT) techniques and security investigation methodologies.

The objectives were to:

* Analyze suspicious domains and URLs
* Perform WHOIS and DNS intelligence gathering
* Identify malicious Indicators of Compromise (IOCs)
* Validate domain reputation using threat intelligence sources
* Document structured investigation workflow
* Recommend defensive mitigation strategies

---

## 🔎 Investigation Methodology

### 1️⃣ Initial Suspicious Domain Analysis

* Reviewed suspicious URL/domain structure
* Checked for typosquatting or brand impersonation
* Identified suspicious TLD usage and domain patterns

---

### 2️⃣ WHOIS & Registration Intelligence

Performed WHOIS lookups to extract:

* Domain creation date
* Registrar information
* Registrant details (if available)
* Hosting provider
* Name server information

Indicators of malicious intent included:

* Recently registered domains
* Privacy-shielded registrant details
* Inconsistent geographic hosting patterns

---

### 3️⃣ DNS & Infrastructure Analysis

Investigated:

* A records (IP mapping)
* MX records (mail server configuration)
* NS records (name servers)
* Hosting ASN

This helped identify potential malicious hosting infrastructure and shared attacker environments.

---

### 4️⃣ Reputation & Threat Intelligence Validation

Cross-referenced domain and IP reputation using:

* VirusTotal
* AbuseIPDB
* PhishTank alternatives
* Passive DNS lookups
* Public threat intelligence feeds

Findings included:

* Previously reported phishing activity
* Suspicious IP reputation scores
* Blacklist presence across security vendors

---

## 🧾 Indicators of Compromise (IOCs) Identified

* Malicious domain(s)
* Associated IP address(es)
* Suspicious name servers
* Hosting ASN
* URL patterns used for credential harvesting

These IOCs can be ingested into SIEM tools for proactive monitoring and blocking.

---

## 🛡️ Risk Assessment

The analyzed domain exhibited characteristics consistent with phishing infrastructure, including:

* Recent registration
* Reputation flags
* Credential harvesting patterns
* Infrastructure reuse indicators

The attack likely targeted user credential theft and potential account compromise.

---

## 🚨 Incident Response Recommendations

Based on investigation findings:

* Block identified domains and IPs at firewall perimeter
* Add IOCs to SIEM watchlists for monitoring
* Enable phishing detection rules in email gateway
* Conduct user awareness communication if applicable
* Monitor for credential abuse attempts (MITRE T1078)

---

## 🎯 MITRE ATT&CK Mapping

* **T1566 – Phishing**
* **T1078 – Valid Accounts**
* **T1583 – Acquire Infrastructure**
* **T1598 – Phishing for Information**

---

## 🔐 Key Skills Demonstrated

* Phishing investigation methodology
* OSINT-based threat intelligence analysis
* IOC extraction and validation
* Domain & DNS intelligence analysis
* Reputation analysis using threat feeds
* Structured SOC documentation workflow

---

## 📌 Future Enhancements

* Automate IOC ingestion into SIEM
* Build phishing detection correlation rules
* Develop Python-based domain enrichment script
* Integrate API-based threat intelligence feeds

---

## 👤 Author

Ansuman Vadapalli
GitHub: https://github.com/Anshu-soc
LinkedIn: https://www.linkedin.com/in/ansuman-vadapalli-9526823b0/
