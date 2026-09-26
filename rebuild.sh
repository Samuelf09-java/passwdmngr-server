#! /bin/bash

sudo systemctl stop passwdmngrd.service
make
sudo make install
sudo systemctl start passwdmngrd.service
