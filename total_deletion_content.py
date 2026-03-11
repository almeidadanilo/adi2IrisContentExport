import json
import datetime
import os
import requests                                 # type: ignore
import argparse
import boto3                                    # type: ignore
import logging
import sys
import uuid
from datetime import timezone
from cryptography.fernet import Fernet          # type: ignore
from pathlib import Path                        # type: ignore
from boto3.s3.transfer import TransferConfig    # type: ignore

######################################################################################################
# Global variables
######################################################################################################
input_file = ''
output_file = "./output.ini.json"
output_f_extension = '.cnt.jsonl'
outURL = ''
outCID = ''
outCSC = ''
outAUT = ''
outGTP = ''
outACR = ''
out_headers = ''
outBucket = ''
outKVP = ''
irisTK = ''
irisTN = ''
irisTKExpire = 0
jsonlFile = ''
del_files = []
c_key = ''

logger = logging.getLogger("vod_cleanup_logger")

__CURRENT_VERSION__ = 'v1.12'

######################################################################################################
# Setup the logging mechanics
######################################################################################################
def setup_logger(mode, level='info'):

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    if mode == 'file':
        handler = logging.FileHandler('vod_total_cleanup.log')
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(formatter)

    if level == 'debug':
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.addHandler(handler)

######################################################################################################
# Load de latest generated crypto key
######################################################################################################
def getCryptoKey():
    logger.info("Getting Crypto Key")
    return open("secret.key", "rb").read()

######################################################################################################
# Returns the decrypted data
######################################################################################################
def decrypt(enc_data):
    global c_key

    if c_key == '':
        c_key = getCryptoKey()
        logger.debug(f"Key acquired: {''}")
    
    fer = Fernet(c_key)

    return fer.decrypt(enc_data.encode()).decode()

######################################################################################################
# Get Output Credentials
######################################################################################################
def getOutputItems(iristenant):
    global outURL, outCID, outCSC, outAUT, outGTP, irisTN, outBucket, outKVP, outMetadata, outACR

    logger.debug("Enter getOutputItems")
    if iristenant == "":
        logger.info("Iris Tenant not informed")
        return False

    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as read_output:
                json_data = json.load(read_output)
                logger.debug(f"Iris Tenant: {iristenant}")
                for item in json_data["items"]:
                    if iristenant == item["iristenant"]:
                        outURL = decrypt(item["URL"])
                        logger.debug(f"Iris Authorization API: {outURL}")
                        outGTP = decrypt(item["GT"])
                        #logger.debug(f"Iris Grants: {outGTP}")
                        outAUT = decrypt(item["AU"])
                        #logger.debug(f"Iris Authorize Entity: {outAUT}")
                        outCID = decrypt(item["CI"])
                        #logger.debug(f"Iris ClientID: {outCID}")
                        outCSC = decrypt(item["CS"])
                        #logger.debug(f"Iris ClientS: {outCSC}")
                        irisTN = item["iristenant"]
                        outBucket = decrypt(item["BK"])
                        #logger.debug(f"Iris Upload Bucket: {outBucket}")
                        outKVP = decrypt(item["KVP"])
                        #logger.debug(f"Iris KVP API: {outKVP}")
                        outACR = decrypt(item["ACR"])
                        #logger.debug(f"Iris AWS: {outACR}")
                        outMetadata = item["METADATA"]
                        #logger.debug(f"Export ADI Metadata: {outMetadata}")
                        return True

        except Exception as e:
            logger.info("Error reading output file")
            logger.debug(f"Error reading output file: {e}")
            return False
    else:
        logger.debug(f"{output_file} does not exist in the script directory.")

    logger.debug("Exit getOutputItems")

######################################################################################################
# Get Iris Access Token
######################################################################################################
def getIrisAccessToken():
    global irisTK, irisTKExpire, outCID, outCSC, outAUT, outGTP

    try:

        headers = {"content-Type": "application/json"}

        payload = {
            "client_id": f"{outCID}",
            "client_secret": f"{outCSC}",
            "audience": f"{outAUT}",
            "grant_type": f"{outGTP}"
        }

        response = requests.post(outURL, headers=headers, json=payload)

        if response.status_code == 200:
            token_data = response.json()
            irisTK = token_data.get("access_token")
            exp = token_data.get("expires_in")
            now = datetime.datetime.now(timezone.utc)
            irisTKExpire = now + datetime.timedelta(seconds=exp)
            logger.debug(f"Iris Access Token Acquired, exiring in: {irisTKExpire}")
        else:
            logger.debug("Iris Acces Token Not Accepted")
            logger.debug(response.status_code, response)
            irisTK = ''

    except Exception as e:
        logger.error(f"Error getting Iris access token: {e}")


######################################################################################################
# Create BOTO client for AWS access
######################################################################################################
def create_boto3_client():
    global irisTK, out_headers, irisTN, outACR

    try:
        logger.debug("Entering create_boto3_client")

        myURL = outACR
        headers = {"Authorization": irisTK}
        response = requests.post(myURL, headers=headers)
        responseJSON = response.json()

        AccessKeyId = responseJSON['AccessKeyId']
        SecretAccessKey = responseJSON['SecretAccessKey']
        SessionToken = responseJSON['SessionToken']

        client = boto3.client(
            's3',
            aws_access_key_id = AccessKeyId,
            aws_secret_access_key = SecretAccessKey,
            aws_session_token = SessionToken
        )
        out_headers = {"content-Type": "application/json", "X-iris-tenantId": irisTN,"Authorization": irisTK}

    except Exception as e:
        logger.error(f"Error create_boto3_client: {e}")
        return None

    logger.debug("Exiting create_boto3_client")
    return client

######################################################################################################
# Push the jsonl file to AWS through BOTO
######################################################################################################
def send_jsonl(client, file):
    global outBucket, irisTN
    try:
        logger.debug("Entering send_jsonl")
        s3_bucket_file_path = irisTN + "/content/deleted/" + file.replace('./del/', '')
        logger.debug(f"jsonlFile: {file}")
        logger.debug(f"outBucket: {outBucket}")
        logger.debug(f"s3_bucket_file_path: {s3_bucket_file_path}")
        logger.debug(f"irisTN: {irisTN}")

        config = TransferConfig(use_threads=False)
        response_put = client.upload_file(
            file.replace('./', ''),
            outBucket,
            s3_bucket_file_path,
            Config=config
        )
        logger.debug(f"Response: {response_put}")
        
    except Exception as e:
        logger.error(f"Error send_jsonl: {e}")

    logger.debug("Exiting send_jsonl")

######################################################################################################
# Adds to the deletion file
######################################################################################################
def add_to_deletion_file(data):
    global del_files
    try:
        fname = f"./del/{str(uuid.uuid4())}.jsonl"
        logger.debug(f"Writting del file {fname}")
        with open(fname, "w", encoding="utf-8") as f1:
            for item in data:
                json.dump(item, f1)
                f1.write("\n")
        
        del_files.append(fname)
        logger.debug(f"Wrote del file {fname} with {len(data)} contentIds")
    except Exception as e:
        logger.error(f"Error add_to_deletion_file: {e}")
######################################################################################################
# Builds the clean up file list
######################################################################################################
def build_deletion_files():
    try:
        content_list = []
        counter = 0
        url = 'https://backoffice-eu2.ads.iris.synamedia.com/content-inventory/content/?limit=5000'
        headers = {"content-Type": "application/json", "Authorization": irisTK}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            contents = data.get('content', '')
            for content in contents:
                cnt = content.get('contentId', '')
                if cnt != "":
                    a = {"contentId": cnt}
                    content_list.append(a)
                counter += 1
                if counter >= 950:
                    add_to_deletion_file(content_list)
                    content_list = []
                    counter = 0
                #endif
            #endfor
            if len(content_list) > 0:
                add_to_deletion_file(content_list)
                content_list = []
        else:
            logger.error(f"build_deletion_files bad content /get API response: {response.status_code}")
        #endif
    except Exception as e:
        logger.error(f"Error build_deletion_files: {e}")

######################################################################################################
# Main Loop
######################################################################################################
parser = argparse.ArgumentParser()
parser.add_argument('-tenant', type=str, default='',help='ADI input file (.xml)')
args = parser.parse_args()
iristenant = args.tenant or ''

setup_logger('file', 'debug')

logger.debug("#######################################")
logger.debug(f'# BEGIN PROCESSING {os.path.basename(__file__)} {__CURRENT_VERSION__}')
logger.debug("#######################################")

if (not(getOutputItems(iristenant))):
    logger.debug ('Error getting output items')
    sys.exit(1)

# Build Iris Access Token
if irisTK == '':
    logger.debug("Calling getIrisAccessToken")
    getIrisAccessToken()

# Builds the deletion (clean_up) list
logger.debug("Building the deletion - full clean-up - file list")
build_deletion_files()

# Create BOTO client
logger.debug("Creating BOTO client")
bot = create_boto3_client()
# Push the jsonl file to AWS Folder
logger.debug("Sending the delete jsonl flies to S3 bucket")
for fl in del_files:
    logger.debug(f"Sending {fl}")
    send_jsonl(bot, fl)

logger.debug("#######################################")
logger.debug('# END PROCESSING ')
logger.debug("#######################################")