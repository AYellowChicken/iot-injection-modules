# IoT Packet Injection Project

!- README and requirements to complete -!

## Overview

The IoT Packet Injection Project is a Python-based framework that leverages the KillerBee module and sniffer hardware to capture, analyze, and manipulate packets in IEEE 802.15.4 layer 2 networks in order to perform various network packet injection. This project is particularly focused on ZigBee networks but can be extended to work with any IEEE 802.15.4 network. It includes a "replay" module essential for defining packet transmission, listening, and response mechanisms.

## Project Components

### Sniffer

The sniffer can be used to listen and write a pcap file containing the ZigBee packets.

### Replay Module

The "replay" module is the core component of this project, responsible for sending specially crafted packets and managing their responses. It defines the behavior of the sniffer hardware, enabling the project to interact with IoT devices and networks.

### Generic Module

A "generic_module" folder contains a "module_interface.py" file that serves as a template for creating custom IoT injection modules. Developers can use this interface to design their own modules, building on the replay module's capabilities.

### Example Modules

The project includes several example modules demonstrating successful IoT network injections:

1. **zcl_alarm**: This module triggers an alarm on IoT house hardware, showcasing how to manipulate and interact with IoT devices for security or automation purposes.

2. **zcl_deconz_temperature** and **zcl_temperature**: These modules change the temperature detected by IoT house hardware. They illustrate how to manipulate sensor data and simulate environmental changes in IoT networks.

3. **zcl_onoff**: This module demonstrates how to control IoT lightbulbs, turning them on and off to send Morse messages or perform other actions in the network.

## Usage

To use this project, follow these steps:

1. **Setup**: Ensure you have the necessary hardware and the KillerBee module installed.

2. **Run**: Execute the desired module based on your specific IoT injection requirements. Each module is an example of how to interact with IoT networks and can serve as a reference for creating your own custom modules.

3. **Customization**: If your IoT network injection needs go beyond the provided examples, consider creating your own module using the "generic_module" template. Customize the module to suit your use case.