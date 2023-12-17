# ELF-Code-Injection

This program injects a payload into all ELF files within the current directory.

## Payload

The virus contains a payload that sends a POST request (with an empty body) to my web server and then the injected file continues to run normally. My web server logs the time at which the request was made and stores it in a database that can be viewed here. You will be able to see if running an infected file succesfully contacted my web server by examining the timestamps at the provided link.

## Installation

To run this virus download the VM with the virus pre-installed here. 
