# PyTorch Network Analyzer

## Project Purpose

The aim of this project is to develop a deep learning model using PyTorch to analyze baseline data and detect common threat behaviors in network traffic. The model will enhance cybersecurity by providing alerts and offering a comprehensive understanding of device interactions on the network. This will assist cybersecurity and information security managers in effectively protecting their networks.


## Project Overview

### Data Processing and Baseline Creation

1. **Packet Traffic Processing**: 
    - Develop a Python script to process packet traffic data from PCAP files.
    - Establish a database using MySQL to store daily, weekly, monthly, and yearly baselines for each device on the network, identified by MAC addresses.

2. **Baseline Data Storage**:
    - Store detailed information about each device's network activity, such as:
        - Initial connection time
        - Duration of activity
        - Average packet rate
        - VPN usage
        - Traffic spikes
        - Comparison against baseline traffic
        - New device communication
        - Unusual activity or protocols
        - Foreign IP origin (known or unknown)
    - Maintain historical baselines to allow retrospective analysis.

3. **Baseline Updates**:
    - Create daily baselines that contribute to weekly, monthly, and yearly summaries.
    - Ensure all daily baselines are preserved to facilitate long-term analysis and context understanding.


### Threat Analysis Using PyTorch

1. **Real-Time Data Analysis**:
    - Use the generated baselines and known threat behaviors to train the PyTorch model.
    - The model will monitor for unusual activities and potential threats, providing alerts starting from the second day of baseline creation.

2. **Alerting and Reporting**:
    - PyTorch will evaluate devices with concerning flags and anomalies.
    - Alerts and ratings of concern will be communicated to security managers or relevant personnel.


## Project Workflow

1. **PCAP File Processing**:
    - Scan PCAP files to extract packet data, including MAC addresses, IP addresses, destinations, protocols, etc.

2. **Network Behavior Analysis**:
    - Identify and flag behaviors such as VPN usage, new connections, unusual protocols, and other anomalies.

3. **Baseline and Historical Data Utilization**:
    - PyTorch analyzes incoming data and uses historical baselines to understand device behavior over time.
    - Reference historical PCAP files for deeper context when needed.

4. **Alert Generation**:
    - Generate alerts or concern ratings based on analysis, and notify security managers.


## Future Goals for the Project

1. **Automated Batch Processing**:
    - Transition from manually scanning PCAP files to automated processes for creating baselines and training the PyTorch model.
    - Aim to handle network packet traffic in manageable batches or through real-time capture for immediate analysis and storage.
    - Ensure continuous traffic monitoring by processing these batches sequentially.

2. **Enhanced PCAP File Management**:
    - Develop a robust system for creating and maintaining PCAP files to facilitate future reference and in-depth analysis as needed.
    
3. **Django Interface**:
    - Web interface (Django) to display alerts and suspicious activity from the PyTorch model.
    - Users can review and approve traffic, improving model accuracy over time.


## Summary

By combining detailed baseline data with advanced threat detection techniques, this project will provide a robust tool for network security management. The integration of PyTorch for real-time analysis ensures that any deviations or potential threats are promptly identified and addressed.
