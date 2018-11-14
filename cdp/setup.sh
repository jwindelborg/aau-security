#!/usr/bin/env bash

rm -rf /etc/update-motd.d/99-one-click

wget -O .vimrc https://gist.githubusercontent.com/jwindelborg/03a59a13495ccf2351118c691a81e035/raw/58be01c2f62b8fd49fb123df5d85b1b7dc6a9454/.vimrc
vim

apt-get update
apt-get upgrade
apt-get dist-upgrade
apt-get autoremove

apt-get install python3-pip

pip3 install -U pychrome

docker pull fate0/headless-chrome

docker run -d --name chrome -it --rm --cap-add=SYS_ADMIN -p9222:9222 fate0/headless-chrome

export DEBUG=1

echo -e "alias debug-on='export DEBUG=1'\nalias debug-off='export DEBUG=0'\nalias stop-chrome='docker stop chrome'\nalias start-chrome='docker run -d --name chrome -it --rm --cap-add=SYS_ADMIN -p9222:9222 fate0/headless-chrome'" > .bash_aliases
source .bashrc
