import os

import dotenv

dotenv.load_dotenv()

# Netbox parameters
NB_URL='http://<ip>:8000'
NB_TOKEN=''

# Device connection parameters
DEV_USERNAME=''
DEV_PASSWORD=None
DEV_KEYFILE=''

# Some Ubiquiti devices only support a single admin account, so a dedicated
# DEV_USERNAME account can't be created on them. When set (via .env), drivers
# try these credentials first and fall back to DEV_USERNAME/DEV_PASSWORD.
# Set DEV_UBNT_USERNAME/DEV_UBNT_PASSWORD in a gitignored .env file.
DEV_UBNT_USERNAME = os.environ.get('DEV_UBNT_USERNAME')
DEV_UBNT_PASSWORD = os.environ.get('DEV_UBNT_PASSWORD')

# Global definitions
LOGGING_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
