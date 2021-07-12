# Projects for ASU CSE548

These are assignments from Arizona State University (ASU), May 2021.

![ASU Ira A. Fulton Schools of Engineering](images/asu.png)

# How to use the files here?

Every Folder contains the files dedicated to an assignment.
Download the Word or PDF File called "Project XX" which will explain how to use the other files. 

## Important Notes

- In downloading and reading those assignments, you are acknowledging Arizona State Universities's Academic Integrity Guidelines reported [here](https://www.coursera.org/learn/asu-mcs-onboarding/home/week/3).


# Project 1 - Packet Filter Firewall

In this lab we are exploring how a packet filter firewall works by setting up an environment based on two Linux virtual machines – one working as a dual-homes Gateway client, which can access external networks on one interface – and another set up as a Client, which can only access external networks through the gateway. The gateway will be configured with the Linux iptables firewall and will also enable NAT for selected protocols.
The lab will also setup a web server on the Gateway with a test web page. We will test having full control of the network traffic, allowing only specific protocols for specific destinations at will, by modifying specific parameters in the firewall script.


# Project 2 - SDN-Based Stateless Firewall

In this lab we are exploring how to set up a software defined environment based on mininet and containernet. We also get to practice how to set up an OpenFlow based flow-level firewall on SDN. Finally, we need to set up and practice flow-based firewall filtering policies such as enabling the ability to accept, drop, or reject the incoming flows thus ensuring the safety of the system from malicious attacking network traffic.


# Project 3 - SDN-Based DoS Attacks and Mitigation

In this lab I am emulating Denial of Service (DoS) attacks in an SDN networking environment. DDoS Attacks can target various components in the SDN infrastructure. I am setting up an SDN-based firewall environment based on containernet, POX controller, and Over Virtual Switch (OVS). To mitigate DoS attacks, I have developed a “port security” solution to counter the implemented DoS attacks.
In the lab I am implementing firewall filtering rules in order to implement the required firewall security policies, along with a sequence of screenshots and corresponding illustrations to demonstrate how I have fulfilled the firewall’s packet filtering requirements.


# Project 4 - Machine Learning-Based Anomaly Detection Solutions

In this lab I am using the NSL-KDD dataset, which is a refined version of KDD’99 dataset, with the purpose of running two labs for data pre-processing, training and testing using Anaconda, TensorFlow and FNN. NSL-KDD dataset is now considered as one of most common for network traffic and attacks, and it is a benchmark for modern-day internet traffic.
