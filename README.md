# Security Onion - Resources

This repository contains the following resources:


## Security Onion specific Sigma Rules
  - Location: `main` branch, sigma folder
  - License: Elastic-2.0
    
This Sigma ruleset is maintained by Security Onion and is loaded by default into the Security Onion Detections' module.

  
## Event Filters
  - Location: `main` branch, event_filters folder
  - License: MIT
    
Generic event filters for process_creation, dns_query, file_create and more. Used by Security Onion to generate event filters for Elastic Defend events.

Originally sourced from https://github.com/Neo23x0/sysmon-config and https://github.com/olafhartong/sysmon-modular


## AI-Generated Detection Summaries
  - Location: `generated-summaries-published` branch, detections-ai folder
  - License: Elastic-2.0

Summaries created by an LLM for Suricata, Sigma and YARA rules. Used by Security Onion in the Detections' module.
