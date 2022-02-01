# Packet Sniffer in Golang
This project was developed as part of the Computer Networks course at Ferdowsi University of Mashhad. It presents a powerful packet sniffer written in Golang, capable of monitoring network traffic and analyzing various network protocols.

## Overview
A packet sniffer is a valuable tool for network administrators, security professionals, and developers, allowing them to inspect and understand network traffic in real-time. This Go-based packet sniffer listens to your network interface and dissects each captured packet to reveal critical information about the communication protocols being used. Supported protocols include:

- Ethernet: Provides information about the data link layer.
- HTTP: Allows you to view HTTP request and response details.
- ARP: Displays Address Resolution Protocol information.
- ICMPv4: Unveils details about Internet Control Message Protocol for IPv4.
- IPv4: Reveals information related to the Internet Protocol version 4.
- SSH: Shows SSH packet details.
- TCP: Provides insights into Transmission Control Protocol (TCP) packets.
- UDP: Offers information on User Datagram Protocol (UDP) packets.

## Features
- Real-time network packet capture and analysis.
- Multifaceted protocol support for comprehensive network monitoring.
- Easy-to-use command-line interface.
- Cross-platform compatibility thanks to Go's portability.
- Educational tool for learning about network protocols and packet analysis.