# ADIContent2IrisContent

This Python script parses **ADI XML metadata files** (e.g., from VOD systems), extracts relevant metadata, transforms it into a structured JSON format, and optionally **sends it to a Synamedia Iris Ad Server content ingestion endpoint**, along with dynamically managed KVPs (Key-Value Pairs).

---


## 📌 Features

- ✅ Parses ADI XML with nested `<Asset>` elements
- ✅ Extracts VOD metadata (title, genres, actors, languages, etc.)
- ✅ Dynamically builds metadata output based on a configurable list (`METADATA`)
- ✅ Supports KVP synchronization with Iris (create/update)
- ✅ Generates `.jsonl` output for ingestion pipelines
- ✅ Optional AWS S3 upload via boto3
- ✅ Logging with `info` and `debug` levels

---

## 📁 Folder Structure

```
├── ADIContent2IrisContent.py       # Main ingestion and transformation script
├── output.ini.json                 # Encrypted credentials and `outMetadata` keys (*) you must contact Synamedia in order to  get this file
├── secret.key                      # Key used for decryption (*) you must contact Synamedia in order to  get this file
├── *.cnt.jsonl                     # Output files generated
└── vod_ingest.log                  # Logging output (if using file mode)
```

---

## ⚙️ Prerequisites

- Python 3.7+
- Required packages:
  ```bash
  pip install boto3 cryptography requests
  ```

---

## 🔐 Configuration (`output.ini.json`)

Example:
```json
{
  "items": [
    {
      "iristenant": "<TENANT_ID",
      "URL": "<encrypted>",
      "GT": "<encrypted>",
      "AU": "<encrypted>",
      "CI": "<encrypted>",
      "CS": "<encrypted>",
      "BK": "<encrypted>",
      "KVP": "<encrypted>",
      "ACR": "<encrypted>",
      "METADATA": [
        "CntProviders",         -- from <ADI><Asset><Metadata><AMS Provider_ID/>
        "CntProducts",          -- from <ADI><Asset><Metadata><AMS Product/>
        "CntAdvisories",        -- from <ADI><Asset><Metadata><App_Data Name="Advisories" />
        "CntCategories",        -- from <ADI><Asset><Metadata><App_Data Name="Category" />
        "CntGenres",            -- from <ADI><Asset><Metadata><App_Data Name="Genre" />
        "CntAudiences",         -- from <ADI><Asset><Metadata><App_Data Name="Audience" />
        "CntProductionYear",    -- from <ADI><Asset><Metadata><App_Data Name="Year" />
        "CntActors",            -- from <ADI><Asset><Metadata><App_Data Name="Actors" />
        "CntDirectors",         -- from <ADI><Asset><Metadata><App_Data Name="Director" />
        "CntProducers",         -- from <ADI><Asset><Metadata><App_Data Name="Producers" />
        "CntStudios",           -- from <ADI><Asset><Metadata><App_Data Name="Studio" />
        "CntCountryOfOrigin",   -- from <ADI><Asset><Metadata><App_Data Name="Country_of_Origin" />
        "CntParentalRating",    -- from <ADI><Asset><Metadata><App_Data Name="Rating" />
        "CntAwards",            -- from <ADI><Asset><Metadata><App_Data Name="X_Award" />
        "CntResolutions",       -- from <ADI><Asset><Asset><Metadata><App_Data Name="Resolution" (when <AMS Asset_Class="movie"/>) />
        "AudioLanguages",       -- from <ADI><Asset><Asset><Metadata><App_Data Name="Languages" (when <AMS Asset_Class="movie"/>) />
        "SubtitleLanguages"     -- from <ADI><Asset><Asset><Metadata><App_Data Name="Subtitle_Languages" (when <AMS Asset_Class="movie"/>) />
      ]
    }
  ]
}

The kvp in Iris will be represented as: key={METADATA.key}, Value={values from ADI}
To not process one or more of the metadata listed, simply remove the entry from metadata in `output.ini.json`.
This script do not print any information in the prompt, it logs everything in the `vod_ingest.log` file, cumulative.
For asset exipiration o Iris ingested data collection the script offer a variable caller `expirationBias` default set to 365 (days) should present the amount of days for the ingested content to expire in Iris.

```

> 🛡️ Values must be encrypted using your `secret.key` via the same Fernet encryption used by the script.

---

## 🧪 How to Run

```bash
python ADIContent2IrisContent.py \
  -input "myADI.xml" \
  -output "IRIS_TENANT_ID" \
  -log file \
  -level debug
```

**Arguments:**
- `-input`: ADI XML file to parse
- `-output`: Tenant ID to use in `output.ini.json`
- `-log`: Log output (either `file` or `console`)
- `-level`: Log verbosity (`info` or `debug`)

---

## 📤 Output

- JSONL file (e.g., `20250630_103101.cnt.jsonl`)
- Includes `contentId`, `contentName`, and filtered `metadata`
- Only includes metadata fields listed in the `METADATA` array from `output.ini.json`
- This script output two files one following jsonl standard where every line is a complete json object and another with idents, easier to    read if needed. The file ingested on Iris is the jsonl one.
---

## 🛠️ Functions of Interest

- `fetchAndPrepareADIData()`: Parses the XML, builds the metadata object
- `processKVP()`: Adds or updates KVP values in Iris
- `saveMetadataFile()`: Writes `.jsonl` and `.json` files
- `getOutputItems()`: Loads and decrypts tenant credentials and settings

---

## 🚧 TODO / Improvements

- Add recursive parsing for deeply nested assets
- Option to decrypt with environment variables instead of `secret.key`
- Validate `outMetadata` keys against Iris schema constraints
- Delete already processed `*.jsonl` files

---

## 📞 Support

For issues or feature requests, please contact:  
**Danilo de Almeida**  
📧 [dalmeida@synamedia.com]

---
