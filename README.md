# PyTorch Network Analyzer

## How to use project

1. **Ensure you have git downloaded.**
    - Go to https://www.git-scm.com/ to download the most recent version.
2. **Cloning the project**
    - Go to the command line or Git Bash which should be installed when installing Git. I prefer using Git Bash. Once you are in there go to the             directory you would like to clone the repo too.
    - Once you are there use this command: **git clone https://github.com/nmsu-senior-project/pytorch-network-analyzer.git**
    - You should now see a new folder named pytorch-network-analyzer
3. **Python venv creation and activation**
    - Prior installation of VENV may be needed. VENV creates a virtual environment (venv) for our project to run which allows us to install modules          and libraries in to the venv without impacting other projects or vice versa.
    - Change your directory in the command line to the newly cloned project folder and paste this command **python -m venv venv**
    - You should see another folder created within the project folder.
    - **YOU WILL WANT TO ACTIVATE THIS BEFORE RUNNING THE PROJECT EVERY TIME.**
    - In order to activate the venv go to the command line and type **source venv/Scripts/activate** for Windows and **source venv/bin/activate** for        Linux.
4. **Install Libraries**
    - In the command line after the activation of your venv complete these commands:
        - **pip install scapy mysql-connector-python**
5. **Create a MySQL server on your local machine**
    - Install MySQL from this link: https://dev.mysql.com/downloads/installer/
    - Create a basic localhost server or custom domain server whichever you may need.
    - You can utilize application such as DBeaver to connect to your localhost server if you need a GUI.
    - Inside DBeaver you can create some basic users that have basic permissions. I recommend three users espically if you are using just the basic          MYSQL server application you will need it in order to have multiple queries taking place at once.
      
    - After creating these users on your MySQL server create a credentials.txt file within the analyzer directory that stores the users login information in this manner. This is an example not real use case:
    - db_user:nmsu_user1
    - db_pass:gravity_is_an_illusion2024
    - db_user:nmsu_user2
    - db_pass:gravity_is__an_illusion2025
    - db_user:nmsu_user3
    - db_pass:gravity_is_an_illusion2026
  

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
