# ELF-Code-Injection

This program injects a payload into all ELF files within the same directory.

## Payload

The virus contains a payload that sends a POST request (with an empty body) to my web server and then the injected file continues to run normally. My web server logs the time at which the request was made and stores it in a database that can be viewed [here](https://jasonhschwartzman.com/projects/code-injection/timestamps). You will be able to see if running an infected file succesfully contacted my web server by examining the timestamps at the provided link.

## Installation

1. Install virtual box https://www.virtualbox.org/wiki/Downloads
2. Install the VM [here](https://drive.google.com/file/d/1Qb9SvjBNaVAd5I1-dZH-WZu4TrhEl5x2/view?usp=sharing)
3. On virtual box select File -> Import Appliance, then select the download VM, select Next and then Finish.
4. Open the VM
5. Open the Terminal
6. Run the following:
```
sudo su (followed by the password ubuntu)
cd ELF-Code-Injection
```

Now that you are in the directory with virus, inject.py, feel free to add any ELF file to this directory for testing. When you want to run the virus and infect all ELF files in the current directory type 'python3 inject.py'
