#!/bin/bash

# Add kitware key to apt
wget -qO - https://apt.kitware.com/keys/kitware-archive-latest.asc | sudo apt-key add -

# Get kitware (cmake) repo
sudo apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'
sudo apt-get update

sudo apt install -y cmake

