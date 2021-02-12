import os
import enum
from configparser import ConfigParser


def config(filename='database.ini', section='postgresql'):
    # create a parser
    parser = ConfigParser()
    # read config file
    parser.read(filename)

    # get section, default to postgresql
    db = {}
    if parser.has_section(section):
        params = parser.items(section)
        for param in params:
            db[param[0]] = param[1]
    else:
        raise Exception('Section {0} not found in the {1} file'.format(section, filename))

    return db


# Using enum class create enumerations
class USERSTATUS(enum.Enum):
   USRNN = 0
   USRNE = 1
   USREN = 2
   USRAT = 3

class Config:
    DEBUG = False
    INSTITUTION_NAME: str = 'NHS_CIS'
    LOGO_URL: str = 'https://freeiconshop.com/wp-content/uploads/edd/bank-flat.png'
    WALLET_NAME: str = 'NHS_CIS_Identity_Wallet'
    WALLET_KEY: str = 'NHS_CIS_Identity_Wallet'
    CRED_DEF_ID = "DGCGw4hAwb6ZL1JpmgPwCW:3:CL:173845:latest"
    SCHEMA_ID =  "DGCGw4hAwb6ZL1JpmgPwCW:2:CIS_Digital_Credentials:348.77.579"


class DevelopmentConfig(Config):
    # uncomment the line below to use postgres
    # SQLALCHEMY_DATABASE_URI = postgres_local_base
    DEBUG = True


class TestingConfig(Config):
    DEBUG = True
    TESTING = True


class ProductionConfig(Config):
    DEBUG = False
    # uncomment the line below to use postgres


config_by_name = dict(
    dev=DevelopmentConfig,
    test=TestingConfig,
    prod=ProductionConfig
)

