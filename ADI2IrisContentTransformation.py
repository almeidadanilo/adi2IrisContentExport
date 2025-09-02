# prerequisites:
#     pip install requests
#     pip install boto3
#     pip install paramiko

# Usage:
#       python <script_name>.py -input <Local_ADI_File> -output <Iris_Tenant_ID> -export <yes|no> -deleletefile <yes|no>
#
# 
#
# Version:
# v1.5 - Coded and Tested with multiple ADI input files.
#           <Danilo Almeida>

import json
import datetime
import os
import requests                         # type: ignore
import argparse
import boto3                            # type: ignore
import time
import logging
import re
import sys
import xml.etree.ElementTree as ET
from datetime import timezone
from cryptography.fernet import Fernet  # type: ignore

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
outMetadata = []
out_headers = ''
outBucket = ''
outKVP = ''
irisTK = ''
irisTN = ''
irisTKExpire = 0
jsonlFile = ''
exportObject = []
c_key = ''
expirationBias = 365
waitingTime = 15
logger = logging.getLogger("vod_logger")
__CURRENT_VERSION__ = 'v1.5'

######################################################################################################
# Setup the logging mechanics
######################################################################################################
def setup_logger(mode, level='info'):

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    if mode == 'file':
        handler = logging.FileHandler('vod_ingest.log')
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
        logger.debug(f"Key acquired: {c_key}")
    
    fer = Fernet(c_key)

    return fer.decrypt(enc_data.encode()).decode()

######################################################################################################
# Check regular expression for alphanumeric + "_"
######################################################################################################
def is_alnum_full(s):
    return bool(re.match(r'^[A-Za-z0-9_]+$', s))

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
                        logger.debug(f"Iris Grants: {outGTP}")
                        outAUT = decrypt(item["AU"])
                        logger.debug(f"Iris Authorize Entity: {outAUT}")
                        outCID = decrypt(item["CI"])
                        logger.debug(f"Iris ClientID: {outCID}")
                        outCSC = decrypt(item["CS"])
                        logger.debug(f"Iris ClientS: {outCSC}")
                        irisTN = item["iristenant"]
                        outBucket = decrypt(item["BK"])
                        logger.debug(f"Iris Upload Bucket: {outBucket}")
                        outKVP = decrypt(item["KVP"])
                        logger.debug(f"Iris KVP API: {outKVP}")
                        outACR = decrypt(item["ACR"])
                        logger.debug(f"Iris AWS: {outACR}")
                        outMetadata = item["METADATA"]
                        logger.debug(f"Export ADI Metadata: {outMetadata}")
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
        logger.info("Error getting Iris access token")
        logger.debug(f"Error getting Iris access token: {e}")


######################################################################################################
# Check whether the KVP already exists in Iris, if not, then create it
######################################################################################################
def processKVP(key, values):
    global irisTK, outKVP

    try:
        logger.debug("Enter processKVP")

        # Ensure the key is respecting the character limit
        if len(key) > 20:
            logger.warning(f"Skipping KVP key {key}: exceeds 20 chars.")
            return

        # Sorts alphabetically or numerically
        ordered_values = sorted(values)  
        body = {
            "key": key,
            "values": ordered_values
        }
        getURL = outKVP + '/' + key
        headers = {"content-Type": "application/json", "Authorization": irisTK}
        logger.debug(f"KVP API URL: {getURL}")
        logger.debug(f"KVP API Body: {body}")

        if irisTK == '':
            return

        response = requests.get(getURL, headers=headers)
        logger.debug(f"KVP API Status Code: {response.status_code}")
        data = response.json()
        if response.status_code == 404:
            # KVP does not exist, needs to be created
            addURL = outKVP
            logger.debug(f"Adding KVP {key}")
            addResponse = requests.post(addURL, headers=headers, json=body)
            if addResponse.status_code != 201:
                logger.debug(f"Failed to add the KVP {key}: {addResponse.status_code}")
                logger.debug(f"Body: {addResponse.json()}")
        elif response.status_code == 200:
            # KVP exists, update the value list
            add = False
            vals = sorted(data.get("values"))
            for vl in values:
                # add to the complete values list only the new items received from "values"
                if vl not in vals:
                    vals.append(vl)
                    add = True
            body = {
                "key": key,
                "values": sorted(vals)
            }            
            updateURL = outKVP + '/' + key
            logger.debug(f"Updating KVP {key}, with {body}")
            if add:
                updateResponse = requests.put(updateURL, headers=headers, json=body)
                if updateResponse.status_code != 204:
                    logger.debug(f"Failed to update the KVP {key}: {updateResponse.status_code}")
                    logger.debug(f"Body: {updateResponse.json()}")
        else:
            logger.debug(f"Unexpected API return: {response.status_code}")
            return
        
        logger.debug("Exit processKVP")

    except Exception as e:
            logger.info("Error Process KVP")
            logger.debug(f"Error Process KVP: {e}")

######################################################################################################
# Format the person name for Iris format and invert last with first name
######################################################################################################
def format_person_name(name):
    if ',' in name:
        last, first = [part.strip() for part in name.split(',', 1)]
        return f"{first}_{last}".replace(' ', '_')
    return name.replace(' ', '_')

######################################################################################################
# Build json response from ADI
######################################################################################################
def fetchAndPrepareADIData(input_file):
    global exportObject

    now = datetime.datetime.now(timezone.utc)
    expirationDate = now + datetime.timedelta(days=expirationBias)
    txtContentID = ''
    txtContentName = ''
    txtEpisodeId = ''
    txtEpisodeName = ''
    txtContentType = 'VOD'
    txtProcessingWindowExpire = ''
    objSubtitles = []
    objAudios = []
    objGenres = []
    objParentalRating = []
    objContentAdvisory = []
    objContentCategories = []
    objContentAudiences = []
    objProductionYear = []
    objActors = []
    objDirectors = []
    objProducers = []
    objStudios = []
    objCountryOfOrigin = []
    objAwards = []
    objResolutions = []
    objProviders = []
    objProducts = []
    objKeywords = []
    objOfferTypes = []
    objOfferNames = []
    #############################################################
    fullGenres = []
    fullParentalRating = []
    fullContentAdvisory = []
    fullSubtitles = []
    fullAudios = []
    fullProductionYears = []
    fullContentCategories = []
    fullContentAudiences = []
    fullActors = []
    fullDirectors = []
    fullProducers = []
    fullStudios = []
    fullCountryofOrigin = []
    fullAwards = []
    fullResolutions = []
    fullProviders = []
    fullProducts = []
    fullKeywords = []
    fullOfferTypes = []
    fullOfferNames = []

    try:
        # Load the XML file
        tree = ET.parse(input_file)
        root = tree.getroot()
        # Get the main metadata (package-level)
        package_metadata = root.find('./Metadata')
        package_ams = package_metadata.find('AMS')
        logger.debug(f"Package Asset_Name: {str(package_ams.attrib.get('Asset_Name'))}")
        logger.debug(f"Package Asset_ID: {str(package_ams.attrib.get('Asset_ID'))}")
        #txtContentName = package_ams.attrib.get('Asset_Name', '')
        # Get the content ID from the Metadata > asset_class='title'
        txtContentID = package_ams.attrib.get('Asset_ID', '')
        if txtContentID == '':
            logger.debug("Error getting the content ID.")
            return
        # Get the provider ID from the Metadata > asset_class='title'
        provider_id = package_ams.attrib.get('Provider_ID', '').upper()
        if provider_id != "":
            objProviders.append(provider_id)
            if provider_id not in fullProviders:
                fullProviders.append(provider_id)
        # Get the product ID from the Metadata > asset_class='title'
        product_id = package_ams.attrib.get('Product', '').upper()
        if product_id != "":
            objProducts.append(product_id)
            if product_id not in fullProducts:
                fullProducts.append(product_id)
        # Iterate through assets
        for asset in root.findall('./Asset'):
            txtEpisodeId = ''
            txtEpisodeName = ''
            txtContentName = ''
            asset_metadata = asset.find('Metadata')
            ###################################################################
            # Process the Title ADI section
            ###################################################################
            for app_data in asset_metadata.findall('App_Data'):
                name = str(app_data.attrib.get('Name'))
                value = str(app_data.attrib.get('Value'))
                #if name in ['Resolution','Languages','Subtitle_Languages','X_DAI_Enabled']:
                #print(name)
                # get and parse the content title
                if name == 'Title':
                    if value != '':
                        txtContentName = value.strip()
                # get and parse the EpisodeID in case of series
                if name == 'Episode_ID':
                    txtEpisodeId = value.strip()
                # get and parse the EpisodeName in case of series
                if name == 'Episode_Name':
                    txtEpisodeName = value.strip()
                # get and parse the content advisories
                if name == 'Advisories':
                    advisory_id = value.replace(' ','_').upper()
                    if advisory_id != "":
                        objContentAdvisory.append(advisory_id)
                        if advisory_id not in fullContentAdvisory:
                            fullContentAdvisory.append(advisory_id)
                # get and parse content categories
                if name == 'Category':
                    category_id = value.replace(' ','_').upper()
                    if category_id != "":
                        objContentCategories.append(category_id)
                        if category_id not in fullContentCategories:
                            fullContentCategories.append(category_id)
                # get and parse content genres
                if name == 'Genre':
                    genre_id = value.replace(' ','_').upper()
                    if genre_id != "" and is_alnum_full(genre_id):
                        objGenres.append(genre_id)
                        if genre_id not in fullGenres:
                            fullGenres.append(genre_id)
                # get and parse content audiences
                if name == 'Audience':
                    audience_id = value.replace(' ','_').upper()
                    if audience_id != "":
                        objContentAudiences.append(audience_id)
                        if audience_id not in fullContentAudiences:
                            fullContentAudiences.append(audience_id)                
                # get and parse production year
                if name == 'Year':
                    production_id = str(value)
                    if production_id != "":
                        objProductionYear.append(production_id)
                        if production_id not in fullProductionYears:
                            fullProductionYears.append(production_id)
                # get and parse actors
                if name == 'Actors' or name == 'Actor':
                    actor_id = format_person_name(value).upper()
                    if actor_id != "":
                        objActors.append(actor_id)
                        if actor_id not in fullActors:
                            fullActors.append(actor_id)         
                # get and parse directors
                if name == 'Directors' or name == 'Director':
                    director_id = format_person_name(value).upper()
                    if director_id != "":
                        objDirectors.append(director_id)
                        if director_id not in fullDirectors:
                            fullDirectors.append(director_id)
                # get and parse Producers
                if name == 'Producers' or name == 'Producer':
                    producer_id = format_person_name(value).upper()
                    if producer_id != "":
                        objProducers.append(producer_id)
                        if producer_id not in fullProducers:
                            fullProducers.append(producer_id)                    
                # get and parse Studio
                if name == 'Studio':
                    studio_id = value.replace(' ','_').upper()
                    if studio_id != "":
                        objStudios.append(studio_id)
                        if studio_id not in fullStudios:
                            fullStudios.append(studio_id)
                # get and parse Country of Origin
                if name == 'Country_of_Origin':
                    country_id = value.replace(' ','_').upper()
                    if country_id != "":
                        # Handle the cases where multiple countries are informed in a single entry
                        # Check for string '|' as country divisor
                        country_id = country_id.replace('/', '|')
                        if country_id.find('|') >= 0:
                            country_id_parts = gr_id.split('|')
                            for country_sub_id in country_id_parts:
                                if country_sub_id != '':
                                    objCountryOfOrigin.append(country_sub_id)
                                    if country_sub_id not in fullCountryofOrigin:
                                        fullCountryofOrigin.append(country_sub_id)
                        else:
                            objCountryOfOrigin.append(country_id)
                            if country_id not in fullCountryofOrigin:
                                fullCountryofOrigin.append(country_id)         
                # get and parse Parental Control
                if name == 'Rating':
                    parental_id = value.replace(' ','_').upper()
                    if parental_id != "":
                        objParentalRating.append(parental_id)
                        if parental_id not in fullParentalRating:
                            fullParentalRating.append(parental_id)          
                # get and parse the X_Award
                if name == 'X_Award':
                    award_id = value.replace(' ','_').upper()
                    if award_id != "":
                        objAwards.append(award_id)
                        if award_id not in fullAwards:
                            fullAwards.append(award_id)
                # get and parse the X_Keywords
                if name == 'X_Keyword':
                    keyword_id = value.replace(' ','_').upper()
                    if keyword_id != "":
                        objKeywords.append(keyword_id)
                        if keyword_id not in fullKeywords:
                            fullKeywords.append(keyword_id)
                # get and parse the Processing Window
                if name == 'Licensing_Window_End':
                    txtProcessingWindowExpire = value
            ###################################################################
            # Process the sub sessions
            ###################################################################
            for sub_asset in asset.findall('./Asset'):
                sub_metadata = sub_asset.find('./Metadata')
                if sub_metadata is None:
                    continue
                ams = sub_metadata.find('AMS')
                if ams is None:
                    continue
                ams = sub_metadata.find('AMS')
                cls = str(ams.attrib.get('Asset_Class'))
                #print(cls)
                logger.debug(f"SubPackage Asset_Name: {str(ams.attrib.get('Asset_Name'))}")
                logger.debug(f"SubPackage Asset_ID: {str(ams.attrib.get('Asset_ID'))}")
                logger.debug(f"SubPackage Class_ID: {cls}")
                ###################################################################
                # Process the Movie ADI section
                ###################################################################                
                if cls == 'movie':
                    logger.debug(f"Processing SubPackage Class_ID: {cls}")
                    for sub_app_data in sub_metadata.findall('App_Data'):
                        name = str(sub_app_data.attrib.get('Name'))
                        value = str(sub_app_data.attrib.get('Value'))
                        # get and parse Resolution
                        if name == 'Resolution':
                            resolution_id = value.replace(' ','_').upper()
                            if resolution_id != "":
                                objResolutions.append(resolution_id)
                                if resolution_id not in fullResolutions:
                                    fullResolutions.append(resolution_id)
                        # get and parse Audio Languages
                        if name == 'Languages':
                            audio_id = value.replace(' ','_').upper()
                            if audio_id != "":
                                objAudios.append(audio_id)
                                if audio_id not in fullAudios:
                                    fullAudios.append(audio_id)
                        # get and parse Subtitles
                        if name == 'Subtitle_Languages':
                            subtitle_id = value.replace(' ','_').upper()
                            if subtitle_id != "":
                                objSubtitles.append(subtitle_id)
                                if subtitle_id not in fullSubtitles:
                                    fullSubtitles.append(subtitle_id)
                ###################################################################
                # Process the offer-window ADI section
                ################################################################### 
                if cls == 'offer-window':
                    logger.debug(f"Processing SubPackage Class_ID: {cls}")
                    for sub_app_data in sub_metadata.findall('App_Data'):
                        name = str(sub_app_data.attrib.get('Name'))
                        value = str(sub_app_data.attrib.get('Value'))
                        # get and parse offer types
                        if name == 'Offer_Type':
                            offertype_id = value.replace(' ','_').upper()
                            if offertype_id != "":
                                objOfferTypes.append(offertype_id)
                                if offertype_id not in fullOfferTypes:
                                    fullOfferTypes.append(offertype_id)
                        # get and parse offer names
                        if name == 'Product_Name':
                            offername_id = value.replace(' ','_').upper()
                            if offername_id != "":
                                objOfferNames.append(offername_id)
                                if offername_id not in fullOfferNames:
                                    fullOfferNames.append(offername_id)
        #################################################################################################
        #################################################################################################
        metadata_block = {}     
        # Mapping all variable names to the intended JSON keys
        all_metadata_fields = {
            "CntProviders": objProviders,
            "CntProducts": objProducts,
            "CntAdvisories": objContentAdvisory,
            "CntCategories": objContentCategories,
            "CntGenres": objGenres,
            "CntAudiences": objContentAudiences,
            "CntProductionYear": objProductionYear,
            "CntActors": objActors,
            "CntDirectors": objDirectors,
            "CntProducers": objProducers,
            "CntStudios": objStudios,
            "CntCountryOfOrigin": fullCountryofOrigin,
            "CntParentalRating": objParentalRating,
            "CntAwards": objAwards,
            "CntResolutions": objResolutions,
            "AudioLanguages": objAudios,
            "SubtitleLanguages": objSubtitles,
            "CntKeywords": objKeywords,
            "CntOfferTypes": objOfferTypes,
            "CntOfferNames": objOfferNames
        }
        # Add to the objTmp only the items listed in outMetadata
        for key, value in all_metadata_fields.items():
            if key in outMetadata:
                metadata_block[key] = value
        #################################################################################################
        # If is a series, add the episode id and episode name to the content title
        if txtEpisodeId != '' or txtEpisodeName != '':
            txtContentName += ' - ' + txtEpisodeId + ' ' + txtEpisodeName
        #################################################################################################
        objTmp = {
            "contentId": txtContentID,
            "contentName": txtContentName,
            "contentType": [txtContentType],
            "expirationDate": txtProcessingWindowExpire if txtProcessingWindowExpire.strip() != '' else str(expirationDate.isoformat()),
            "control": {"allowAdInsertion": True},
            "metadata": metadata_block
        }

        # Avoiding duplications in the exportObject
        content_id = txtContentID
        if not any(item.get("contentId", "") == content_id for item in exportObject):
            exportObject.append(objTmp)
        objTmp = {}
        
        # Process the unique collected KVPs
        logger.info("Starting to process the KVPs")
        if (len(fullProviders) > 0 and "CntProviders" in outMetadata):
            processKVP("CntProviders", fullProviders)
        if (len(fullProducts) > 0 and "CntProducts" in outMetadata):
            processKVP("CntProducts", fullProducts)
        if (len(fullContentAdvisory) > 0 and "CntAdvisories" in outMetadata):
            processKVP("CntAdvisories", fullContentAdvisory)
        if (len(fullContentCategories) > 0 and "CntCategories" in outMetadata):
            processKVP("CntCategories", fullContentCategories)
        if (len(fullGenres) > 0 and "CntGenres" in outMetadata):
            processKVP("CntGenres", fullGenres)
        if (len(fullContentAudiences) > 0 and "CntAudiences" in outMetadata):
            processKVP("CntAudiences", fullContentAudiences)
        if (len(fullProductionYears) > 0 and "CntProductionYear" in outMetadata):
            processKVP("CntProductionYear", fullProductionYears)
        if (len(fullActors) > 0 and "CntActors" in outMetadata):
            processKVP("CntActors", fullActors)    
        if (len(fullDirectors) > 0 and "CntDirectors" in outMetadata):
            processKVP("CntDirectors", fullDirectors)               
        if (len(fullProducers) > 0 and "CntProducers" in outMetadata):
            processKVP("CntProducers", fullProducers)
        if (len(fullStudios) > 0 and "CntStudios" in outMetadata):
            processKVP("CntStudios", fullStudios)
        if (len(fullCountryofOrigin) > 0 and "CntCountryOfOrigin" in outMetadata):
            processKVP("CntCountryOfOrigin", fullCountryofOrigin)
        if (len(fullParentalRating) > 0 and "CntParentalRating" in outMetadata):
            processKVP("CntParentalRating", fullParentalRating)
        if (len(fullAwards) > 0 and "CntAwards" in outMetadata):
            processKVP("CntAwards", fullAwards)
        if (len(fullResolutions) > 0 and "CntResolutions" in outMetadata):
            processKVP("CntResolutions", fullResolutions)
        if (len(fullAudios) > 0 and "AudioLanguages" in outMetadata):
            processKVP("AudioLanguages", fullAudios)
        if (len(fullSubtitles) > 0 and "SubtitleLanguages" in outMetadata):
            processKVP("SubtitleLanguages", fullSubtitles)
        if (len(fullKeywords) > 0 and "CntKeywords" in outMetadata):
            processKVP("CntKeywords", fullKeywords)
        if (len(fullOfferTypes) > 0 and "CntOfferTypes" in outMetadata):
            processKVP("CntOfferTypes", fullOfferTypes)
        if (len(fullOfferNames) > 0 and "CntOfferNames" in outMetadata):
            processKVP("CntOfferNames", fullOfferNames)
        logger.info("Finished to process the KVPs")

    except TypeError as tp:
        logger.info("Serialization error")
        logger.debug(f"Serialization error: {tp}")
        for i, item in enumerate(exportObject):
            try:
                json.dumps(item)
            except TypeError as inner_e:
                logger.debug(f"exportObject[{i}] failed: {inner_e}")
                logger.debug(json.dumps(item, indent=2, default=str))
                break
    except Exception as e:
        logger.info("Error fetchAndPrepareADIData")
        logger.debug(f"Error fetchAndPrepareADIData: {e}")

######################################################################################################
# Save the metadata structure into the export json file
######################################################################################################
def saveMetadataFile():
    global exportObject, output_f_extension, jsonlFile

    try:
        timestamp = datetime.datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f'./{timestamp}' + output_f_extension
        filenameA = f'./{timestamp}' + '_noindent' + output_f_extension

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(exportObject, f, indent=4)
        
        with open(filenameA, "w", encoding="utf-8") as f1:
            for item in exportObject:
                json.dump(item, f1)
                f1.write("\n")

        jsonlFile = filenameA

    except Exception as e:
        logger.info("Error saveMetadataFile")
        logger.debug(f"Error saveMetadataFile: {e}")

######################################################################################################
# Create BOTO client for AWS access
######################################################################################################
def create_boto3_client():
    logger.debug("Entering create_boto3_client")
    global irisTK, out_headers, irisTN, outACR

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
    logger.debug("Exiting create_boto3_client")
    return client

######################################################################################################
# Push the jsonl file to AWS through BOTO
######################################################################################################
def send_jsonl(client, method):
    logger.debug("Entering send_jsonl")
    global jsonlFile, outBucket, irisTN

    if method == "add":
        s3_bucket_file_path = irisTN + "/content/input/" + jsonlFile.replace('./', '')
    elif method == "delete":
        s3_bucket_file_path = irisTN + "/content/deleted/" + jsonlFile.replace('./', '')
    
    logger.debug(f"jsonlFile: {jsonlFile}")
    logger.debug(f"outBucket: {outBucket}")
    logger.debug(f"s3_bucket_file_path: {s3_bucket_file_path}")
    logger.debug(f"irisTN: {irisTN}")

    response_put = client.upload_file(jsonlFile.replace('./', ''), outBucket, s3_bucket_file_path)

    logger.debug(f"Response: {response_put}")
    logger.debug("Exiting send_jsonl")

######################################################################################################
# Check if the file is processed in the S3 bucket
######################################################################################################
def check_bucket(client):
    logger.debug("Entering check_bucket")

    global outBucket, jsonlFile

    file_name = jsonlFile.replace('./', '')
    fKey = ''

    response = client.list_objects(Bucket=outBucket)
    contents = response['Contents']

    logger.debug(f"Bucket: {outBucket}")
    logger.debug(f"FileName: {file_name}")
    
    for i in range(len(contents)):
        fKey = contents[i]['Key']
        #logger.debug(f"S3 Bucket Files: {fKey}")
        if file_name in fKey:
            logger.debug(f"S3 Bucket Files: {fKey}")
            if 'ingested' in fKey:
                logger.debug(f"{file_name} File Uploaded Successfully.")
            elif 'errinfo' in fKey:
                failed_result = client.get_object(Bucket=outBucket, Key=irisTN + "/content/failed/" + fKey)
                logger.debug(f"ERROR processing {file_name}")
                logger.debug(failed_result)
                logger.debug(failed_result["Body"].read())
            else:
                logger.debug(f"{file_name} File not uploaded or not processed.")
    
    logger.debug("Exiting check_bucket")

######################################################################################################
# Wait function
######################################################################################################
def wait(seconds):
    for i in range(seconds, 0, -1):
        time.sleep(1)


######################################################################################################
# Delete the local files
######################################################################################################
def delete_files():
    global jsonlFile
    try:
        logger.debug("Entering delete_files")

        # Remove the noident one
        if jsonlFile and os.path.exists(jsonlFile):
            os.remove(jsonlFile)
            logger.info(f"Deleted file: {jsonlFile}")
        else:
            logger.warning(f"File not found for deletion: {jsonlFile}")

        # Remove the idented one
        jsonFile = jsonlFile.replace('_noindent', '')
        if jsonFile and os.path.exists(jsonFile):
            os.remove(jsonFile)
            logger.info(f"Deleted file: {jsonFile}")
        else:
            logger.warning(f"File not found for deletion: {jsonFile}")

        logger.debug("Exiting delete_files")
    except Exception as e:
        logger.error("Error delete_files")
        logger.error(f"Error delete_files: {e}")

######################################################################################################
# Main Loop
######################################################################################################
parser = argparse.ArgumentParser()
parser.add_argument('-input', type=str, default='',help='ADI input file (.xml)')
parser.add_argument('-output', type=str, default='',help='Iris Tenant ID')
parser.add_argument('-log', type=str, default='file', choices=['file'], help='Log output destination')
parser.add_argument('-level', type=str, default='debug', choices=['info', 'debug'], help='Log verbosity level')
parser.add_argument('-export', type=str, default='no', choices=['yes','no'], help='If the script will export the generated file to Iris Tenant')
parser.add_argument('-deletefile', type=str, default='no', choices=['yes','no'], help='If the script will delete the json and jsonl files after uploading them to S3 bucket')
args = parser.parse_args()
input_file = args.input
iristenant = args.output

setup_logger(args.log, args.level)

logger.debug("#######################################")
logger.debug(f'# BEGIN PROCESSING {os.path.basename(__file__)} {__CURRENT_VERSION__}")')
logger.debug("#######################################")

if (not(getOutputItems(iristenant))):
    logger.debug ('Error getting output items')
    sys.exit(1)

# Build Iris Access Token
if irisTK == '' and args.export == 'yes':
    logger.debug("Calling getIrisAccessToken")
    getIrisAccessToken()

# Get Go VOD data export 
logger.debug("Fetching Go Catalog")
fetchAndPrepareADIData(input_file)
logger.debug(f"len(exportObject): {str(len(exportObject))}")
logger.debug(f"ExportObject: {exportObject}")
# Save the jsonl file
logger.debug("Saving the jsonl file")
saveMetadataFile()
if len(exportObject) == 0:
    logger.debug ('Error fetching the VOD metadata')
    sys.exit(1)

if args.export == 'yes':
    # Create BOTO client
    logger.debug("Creating BOTO client")
    bot = create_boto3_client()
    # Push the jsonl file to AWS Folder
    logger.debug("Sending the jsonl to S3 bucket")
    send_jsonl(bot, "add")
    # Wait for 'n' seconds
    logger.debug(f"Waiting: {waitingTime}s")
    wait(waitingTime)
    # Check if the file was properly processed
    logger.debug("Checking S3")
    check_bucket(bot)

if args.deletefile == 'yes':
    # Delete the local files
    delete_files()

logger.debug("#######################################")
logger.debug('# END PROCESSING ')
logger.debug("#######################################")