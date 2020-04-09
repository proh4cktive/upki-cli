![ProHacktive](https://prohacktive.io/storage/parameters_images/LmQm4xddzmyFAdGYvQ32oZ9t1P9e8098UubYjnE9.svg "uPKI from ProHacktive.io")

# µPKI-CLI
***NOT READY FOR PRODUCTION USE***
This project has only been tested on few distributions with Python3.6.
Due to python usage it *SHOULD* works on many other configurations, but it has NOT been tested.
Known working OS:
> - Debian 9 Strech
> - Debian 10 Buster
> - Ubuntu 18.04
> - MacOS Catalina 10.15 (without update services)
> - MacOS Mojave 10.14 (without update services)

## 1. About
µPki [maɪkroʊ ˈpiː-ˈkeɪ-ˈaɪ] is a small PKI in python that should let you make basic tasks without effort.
It works in combination with:
> - [µPKI-CA](https://github.com/proh4cktive/upki)
> - [µPKI-RA](https://github.com/proh4cktive/upki-ra)
> - [µPKI-WEB](https://github.com/proh4cktive/upki-web)

µPki-CLI is the client app that interact with the [µPKI-RA](https://github.com/proh4cktive/upki-ra) Registration Authority.

### 1.1 Dependencies
The following modules are required
- Requests

Some systems libs & tools are also required, make sure you have them pre-installed
```bash
sudo apt update
sudo apt -y install build-essential python3-dev python3-pip git
```

## 2. Install
The Installation process require three different phases:

1. clone the current repository
```bash
git clone https://github.com/proh4cktive/upki-cli
cd ./upki-cli
```

2. Install the dependencies and upki-client service timer in order to re-generate local certificates if needed. Registration Authority URL is required at this step 
```bash
./install.sh --url https://certificates.domain.com
```

3. Setup certificates required (cf. Usage below)

## 3. Usage
µPki-CLI is the µPki client and should be installed on server/customer host that will receive the final certificate. µPki-CLI is responsible for private key and certificate request generation.

### 3.1 Add a certificate
*Note: On basic configuration you can add a certificate localy only if it add been registered on RA by an admin. To setup your Registration Authority (RA) please check [µPKI-RA](https://github.com/proh4cktive/upki-ra).*

Call the client script with 'add' action
```bash
./client.py --url https://certificates.domain.com add
```

For browser integration call the client script with 'add' action and browser flags
```bash
./client.py --url https://certificates.domain.com add --firefox --chrome
```

### 3.2 List all certificates
You can list all certificates registered locally (this does not reflect what is configured on the RA server).
```bash
./client.py --url https://certificates.domain.com list
```

### 3.3 Delete a certificate
You can un-register a locally defined certificate (note: this will not affect RA configuration).
```bash
./client.py --url https://certificates.domain.com delete
```

### 3.4 Renew all certificates
You can force a certificate renewal for all certificate, which is basicaly what the upki-client services timer is doing.
```bash
./client.py --url https://certificates.domain.com renew
```

### 3.5 Renew Certificates Revokation List
Re-download CRL, useful when client is a server and web server needs to have an updated list.
An example systemd timer for Nginx is given in *upki-cli-crl.service* and *upki-cli-crl.timer*
```bash
./client.py --url https://certificates.domain.com crl
```

### 3.6 Help
For more advanced usage please check the app help global
```bash
./client.py --help
```

You can also have specific help for each actions
```bash
./client.py --url https://certificates.domain.com add --help
```

## 4. TODO
Until being ready for production some tasks remains:
> - Setup Unit Tests
> - Refactoring of Bot class
> - Migrate storage to TinyDB or sqlite
> - Store URL in config file
> - Associate each node with specific URL in order to allow support for multiple RA
> - Add uninstall.sh script
