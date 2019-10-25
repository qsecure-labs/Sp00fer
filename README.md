# Sp00fer (COMING SOON :))

![alt text](https://github.com/qsecure-labs/Sp00fer/blob/master/spoofer.PNG)

Sp00fer is a tool for mail server testing (e.g. for open mail relays etc.) and for spoofing checks on specified domains.

## Usage (Python3 required):

### Linux:

`git clone https://gitlab.cdma.com.cy/v4kkis/sp00fer.git`

`chmod +x install.sh`

`./install.sh`

`python3 spoofer.py -h`

### Windows (For windows the pcap argument which saves the traffic is not implemented):

`git clone https://gitlab.cdma.com.cy/v4kkis/sp00fer.git`

`pip3 install -r requirements.txt`

`python3 spoofer.py -h`

## JSON file structure

A JSON file is used as a template for each scenario you want to sent. The reserved words which change depending on what you choose in the arguments are:

- **CLIENTEMAIL** which is replaced by the value of the `--email` argument
- **CLIENTDOMAIN** which is replaced by the value of the `--domain` argument
- **CLIENTNAME** which is derived by the value of the `--email` argument's local part (e.g. info@client.com will become "info")
- **TESTERDOMAIN** which is replaced by the value of the `--tester` argument

Example of the JSON is:

```json
[{
    "scenario_no": "1",
    "comment": "Test number 1 description",
    "mailfrom": "CLIENTEMAIL",
    "headerfrom": "CLIENTEMAIL",
    "to": "CLIENTEMAIL",
    "subject": "Test number 1",
    "body": "This is a test e-mail message.\n\nPlease forward it to Pentester@[yourdomain] \n\nThank you,\nTest"
},
{
    "scenario_no": "2",
    "comment": "Test number 2 description",
    "mailfrom": "TESTERDOMAIN",
    "headerfrom": "TESTERDOMAIN",
    "to": "TESTERDOMAIN",
    "subject": "Test number 2",
    "body": "This is a test e-mail message.\n\nPlease forward it to Pentester@[yourdomain] \n\nThank you,\nTest"
}]
```

## Disclaimer
Sp00fer comes without warranty and is meant to be used by penetration testers during approved penetration testing assessments and/or social enigneering assessments. Sp00fer's developers and QSecure decline all responsibility in case the tool is used for malicious purposes or in any illegal context.
