#!/bin/python3
import os
from libs import download_cpe_matches
BASEDIR = os.path.dirname(os.path.realpath(__file__))

# Create a temporary directory to store downloaded files
if not os.path.exists(BASEDIR+'/tmp-nvd/'):
    os.makedirs(BASEDIR+'/tmp-nvd/')

# Downloading CPE matches from NVD feeds
cpe_matches = download_cpe_matches(BASEDIR)
