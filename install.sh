#!/bin/bash

python3 -mplatform | grep -qiE 'Ubuntu|Linux' && {
  sudo apt-get install -y python3 python3-pip git
  pip3 install virtualenv
}
python3 -mplatform | grep -qi centos && {
  sudo yum install -y git python3 python3-pip python3-virtualenv
}
python3 -mplatform | grep -qi macOS && {
  brew update
  brew install python3 git
  python -m ensurepip
  pip install virtualenv
}

virtualenv env --python=python3
env/bin/pip install -r requirements.txt
