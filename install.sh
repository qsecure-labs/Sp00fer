#!/bin/sh

apt install python3
apt install python3-pip
pip3 install git+https://github.com/lunarca/pyemailprotectionslib.git
pip3 install -r requirements.txt
