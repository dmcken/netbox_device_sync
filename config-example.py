'''Config parameters

Copy this file to config.py - all actual values are supplied via a
gitignored .env file (see .env.example), loaded through python-dotenv.
'''

import os

import dotenv

dotenv.load_dotenv()

# Netbox parameters
NB_URL = os.environ.get('NB_URL')
NB_TOKEN = os.environ.get('NB_TOKEN')

# Device connection parameters
DEV_USERNAME = os.environ.get('DEV_USERNAME')
DEV_PASSWORD = os.environ.get('DEV_PASSWORD')
DEV_KEYFILE = os.environ.get('DEV_KEYFILE')

# Some Ubiquiti devices only support a single admin account, so a dedicated
# DEV_USERNAME account can't be created on them. When set (via .env), drivers
# try these credentials first and fall back to DEV_USERNAME/DEV_PASSWORD.
DEV_UBNT_USERNAME = os.environ.get('DEV_UBNT_USERNAME')
DEV_UBNT_PASSWORD = os.environ.get('DEV_UBNT_PASSWORD')

# Global definitions
LOGGING_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
