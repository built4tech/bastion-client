# Bastion - client

Python script to collect device information and send it to Bastion Web Service (https://built4tech.herokuapp.com).

## Setup:

### Step 0:

Consider the creation of a virtual environment

python3 -m venv env

source env/bin/activate

### Step 1:

Clone the repository with the following command

git clone https://github.com/built4tech/bastion-client.git

cd bastion-client

### Step 2:

While the script in charge of detecting systems (monitor.py) doesn't need the application Nmap to work, the script in charge of enriching information about the system detected uses Nmap application, please install this application and be sure it's on the path.

Follow the documentation on https://nmap.org/download.html

In ubuntu the installation of nmap is as simple as:

- Update Ubuntu Package List

sudo apt-get update

- Install Nmap

sudo apt-get install nmap

- Check it is correctly installed

nmap -V

### Step 3:

- Linux

Bastion-client monitors devices using modules that require admin privileges. Install bastion-client requeriments using sudo:

sudo pip install -r requirements.txt

- Windows

pip install -r requirements.txt


## Quick Start:

Get the Bastion token related to your user from https://built4tech.herokuapp.com

Linux

- Execute monitor.py with sudo privileges

sudo python3 monitor.py -t <token-value>

- Execute enriching.py with sudo privileges

sudo python3 enriching.py -t <token-value>

Windows

- Execute monitor.py

python monitor.py -t <token-value>

- Execute enriching.py

python enriching.py -t <token-value>





