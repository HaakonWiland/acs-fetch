import requests
import json
from typing import List, Dict, Any
from datetime import date 
import os 
import psycopg2

# NB - TODO: Need to define the environment variables below before running the script. 
ACS_API_TOKEN = os.getenv("ACS_API_TOKEN")
dbname = os.getenv("DB_NAME")
user = os.getenv("DB_USER")
password = os.getenv("DB_USER_PASSWORD")
host = os.getenv("DB_HOST", "localhost")
port = os.getenv("DB_PORT", "5432")
NIST_API_KEY=os.getenv("NIST_API_KEY")

# NB - TODO: Need to define the url to your ACS instance  
ACS_URL = ""

# NB - TODO: Populate namespace_list with the namespaces you want to get data from 
namespace_list = []

# CVSS database from nist 
cvss_database = {}


def get_cvss_from_nist(cve:str, cvss_database:dict):
    """
        Fetch the nist API to check the CVSS for a given CVE.
    """

    headers = {"apiKey": NIST_API_KEY.strip()}

    # Before we do an api request, check if we have it stored in our cvss dict:
    if cve in cvss_database:
        print(f"Did a caching-lookup for cve: {cve}")
        return cvss_database[cve]
    

    try:
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}", headers=headers)
        alt_cve_database = response.json()
        print(f"NIST API response code: {response.status_code}, CVE: {cve} \n")
        

        # Prioritize cvssV40 > cvssV31 > cvss2
        if "cvssMetricV40" in alt_cve_database["vulnerabilities"][0]["cve"]["metrics"]:
            cvss = alt_cve_database["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV40"][0]["cvssData"]["baseScore"]
        
        elif "cvssMetricV31" in alt_cve_database["vulnerabilities"][0]["cve"]["metrics"]:
            cvss = alt_cve_database["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        else:
            cvss = alt_cve_database["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]

        # append to list, such that we dont have to make the api request more than we have to. 
        cvss_database[cve] = cvss
        
        return cvss 

    except Exception as e:
        print(f"Did not manage to make a sucessful NIST API request for: {cve}, Error: {e}")
        print(f"Setting cvss to -1.")
        cvss = -1
        return cvss


def fetch_vulnerability_data(api_token: str, namespace: str) -> List[Dict[str, Any]]:
    """
    Fetch vulnerability data from the ACS API for a specific namespace.
    
    Args:
        api_token: Bearer token for API authentication
        namespace: Kubernetes namespace to query 
    
    Returns:
        List of vulnerability data entries
    """
    baseurl = ACS_URL
    endpoint = "/v1/export/vuln-mgmt/workloads"
    
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-type": "application/json"
    }
    
    parameters = {
        "query": f"Namespace:{namespace}"
    }
    
    url = baseurl + endpoint
    response = requests.get(url, headers=headers, params=parameters) 
    response.raise_for_status()
    
    data_list = []
    for line in response.text.splitlines():
        if line.strip():  # Skip empty lines
            data_list.append(json.loads(line))
    
    return data_list


def process_vulnerability_data(raw_data: List[Dict[str, Any]], namespace: str) -> List[Dict[str, Any]]:
    """
    Process raw vulnerability data and extract relevant information.
    
    Args:
        raw_data: Raw vulnerability data from API
    
    Returns:
        List of processed vulnerability records
    """
    deployment_vulnerabilities = []
    today = date.today().isoformat()
    
    for data_entry in raw_data:
        deployment_name = data_entry["result"]["deployment"]["name"]
        
        # Extract scan data from the first image (There is only one entry in the raw-json object with name images, and it contains a list with one dict)
        images = data_entry["result"]["images"]
        if not images:
            continue
        
        # Image name of the image ACS is scanning 
        # TODO: Add this to the database. 
        image_name = images[0]["name"]["fullName"]

        # Image hash used to build the deferUrl 
        image_hash = images[0]["id"]

        # Get the image tag 
        image_tag = images[0]["name"]["tag"]

    
        # Image is just a list with one dict, some deployments does not have this?
        # Verify it has the scan data.  
        if not images[0]["scan"]:
            continue

        scan_data = images[0]["scan"]
        components = scan_data.get("components", [])
        
        # Process each component that has vulnerabilities
        # print(f"[+] Looking up extra cvss data for the missing records in acs.")
        for component in components:
            if component == None:
                component = "None-placeholder"
            vulns = component.get("vulns", [])
            if not vulns:
                continue
                
            # Create a record for each vulnerability in the component
            for vulnerability in vulns:
                cve = vulnerability["cve"]
                cvss = vulnerability["cvss"]
                
                # NOTE: Some public vulnerabilities does not start with "cve", but rather "go", "ghsa",etc.. 
                # Only vulns starting with CVE will be available in the NIST api.  
                if cvss == 0 and cve[0:3].upper() == "CVE":
                    cvss = get_cvss_from_nist(cve, cvss_database)
                    

                date_of_discovery = vulnerability.get("firstImageOccurrence", f"today").split("T")[0]
                deferUrl = ACS_URL+f"/main/vulnerabilities/user-workloads/images/{image_hash}?detailsTab=Vulnerabilities&s%5BCVE%5D%5B0%5D={cve}"

                vulnerability_record = {
                    "namespace": namespace,
                    "deployment": deployment_name,
                    "imageTag": image_tag,
                    "component": component["name"],
                    "version": component["version"],
                    "cve": vulnerability["cve"],
                    "cvss": cvss,
                    "summary": vulnerability["summary"],
                    "link": vulnerability["link"],
                    "fixedBy": vulnerability.get("fixedBy", "Unknown"),
                    "date_of_scan": today,
                    "date_of_discovery": date_of_discovery,
                    "state": vulnerability["state"],
                    "imageHash": image_hash,
                    "deferUrl": deferUrl
                }
                deployment_vulnerabilities.append(vulnerability_record)
    
    return deployment_vulnerabilities

def insert_vulnerability_data_postgres(connection, vulnerabilities: list):
    """
        Insert vulnerability records into the database
    """
    cursor = connection.cursor()
    
    insert_query = """
    INSERT INTO vulnerabilities 
    (namespace, deployment, imageTag, component, version, cve, cvss, summary, link, fixedBy, dateofscan, dateofdiscovery, state, imageHash, deferUrl, raw_data)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (namespace, deployment, component, version, cve) DO NOTHING
    RETURNING *; 
    """
    
    skipped_duplicate_count = 0
    inserted_count = 0
    skipped_count = 0
    
    for vuln in vulnerabilities:

        try:
            # Extract values with defaults for missing fields
            namespace = vuln.get('namespace', 'Unknown')
            deployment = vuln.get('deployment', 'Unknown')
            imageTag = vuln.get('imageTag', 'Unknown')
            component = vuln.get('component', 'Unknown')
            version = vuln.get('version', 'Unknown')
            cve = vuln.get('cve', '-1')
            cvss = vuln.get('cvss', 'Unknown')
            summary = vuln.get('summary', '')
            link = vuln.get('link', '')
            fixedBy = vuln.get('fixedBy', 'Unknown')
            dateofscan = vuln.get('date_of_scan', "Unknown")
            dateofdiscovery = vuln.get('date_of_discovery', "Unknown")
            state = vuln.get('state', 'Unknown')
            imageHash = vuln.get('imageHash', 'Unknown')
            deferUrl = vuln.get('deferUrl', 'Unknown')

            cve_dict = {
                "namespace": namespace,
                "deployment": deployment,
                "imageTag": imageTag,
                "component": component,
                "cve": cve,
                "cvss": cvss,
                "state": state
            }
            # state can be "DEFERED" or "FALSE_POSITIVE", notify if we see a state like this
            if state != 'OBSERVED':
                print(f"\nAn entry has NOT-OBSERVED state: {cve_dict}\n")
            
            
            # Convert CVSS to float if it's not already (should not really go into this if statement ever)
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                    # if cvss == 0:
                    #     cvss == -1 #When a CVE has CVSS Unknown in ACS, it is returned as 0 from the API
                except ValueError:
                    cvss = -1 #Some CVEs has CVSS "unknown" in ACS, indicate these with -1.
            
            cursor.execute(insert_query, (
                namespace,
                deployment,
                imageTag, 
                component,
                version,
                cve,
                cvss,
                summary,
                link,
                fixedBy,
                dateofscan,
                dateofdiscovery,
                state,
                imageHash,
                deferUrl,
                json.dumps(vuln)  # Store raw JSON data
            ))

            result = cursor.fetchone()
            
            if result:
                inserted_count += 1
            else:
                skipped_duplicate_count += 1
                print(f"This vulnerability was skipped due to duplication: {vuln}\n")
            
        except Exception as e:
            print(f"Error inserting record: {e}")
            print(f"Problematic record: {vuln}")
            skipped_count += 1
            continue
    
    connection.commit()
    cursor.close()
    
    print(f"\nSuccessfully inserted: {inserted_count} records")
    print(f"Skipped due to error: {skipped_count} records")
    print(f"Skipped due to duplication: {skipped_duplicate_count} records\n")

def get_vulnerability_data_postgres(connection, table_name: str):
    """
        Fetches the raw_data column from a table in ACSDATA database. 
        Returns a list of simplified dicts. 
    """
    cursor = connection.cursor()

    get_vulnerability_data_query = f"""
    SELECT raw_data FROM {table_name} 
    """

    cursor.execute(get_vulnerability_data_query)
    connection.commit()

    vulnerabilities_raw: list[dict] = [row[0] for row in cursor.fetchall()]
    vulnerabilities: list[dict] = []

    for entry in vulnerabilities_raw:
        unique_entry = {"namespace": entry["namespace"], "deployment": entry["deployment"], "component": entry["component"], "cve": entry["cve"]}
        vulnerabilities.append(unique_entry)

    return vulnerabilities


def check_fixed_historical_vulnerabilities(connection, todays_scan: list[dict], yesterday_scan: list[dict]):
    """
        Check if any of the active vulnerabilities in the historical vulnerability
        table has been fixed. 

        Update these vulnerabilities with active=False and DateOfFix=today(). 
    """

    cursor = connection.cursor()

    fixed_vulnerabilities: list[dict] = []

    update_fixed_query = """
        UPDATE historicalvulnerabilities
        SET active = %s,
            dateOfFix = %s
        WHERE namespace = %s
        AND deployment = %s
        AND component = %s
        AND cve = %s
        RETURNING *;
    """
    todays_scan_simplified = [{"namespace": row["namespace"], "deployment": row["deployment"], "component": row["component"], "cve": row["cve"]} for row in todays_scan]

    for vuln in yesterday_scan:
        if vuln in todays_scan_simplified:
            continue
        
        # Then it must have been fixed. 
        elif vuln not in todays_scan_simplified:
            # collect the fixed once for debugging 
            fixed_vulnerabilities.append(vuln)

            cursor.execute(
            update_fixed_query,
                (
                False,
                date.today().isoformat(),
                vuln["namespace"],
                vuln["deployment"],
                vuln["component"],
                vuln["cve"],
                ),
            )
    
    connection.commit()
    print(f"Registered {len(fixed_vulnerabilities)} fixed vulnerabilities.")


def append_vulnerability_data_historical_postgres(connection, today_scan: list, historical_vulnerabilities: list):
    
    """Insert vulnerability records into the historical table"""
 
    cursor = connection.cursor()

    insert_query = """
    INSERT INTO historicalVulnerabilities 
    (namespace, deployment, imageTag, component, version, cve, cvss, dateofscan, dateofdiscovery, state, imageHash, active, dateOfFix, raw_data)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (namespace, deployment, component, version, cve) DO NOTHING
    RETURNING *; 
    """

    skipped_duplicate_count = 0
    inserted_count = 0
    skipped_count = 0
    error_list = []

    for vuln in today_scan:

        unique_vuln = {"namespace": vuln["namespace"], "deployment": vuln["deployment"], "component": vuln["component"], "cve": vuln["cve"]}

        # Check if vuln already exists in historical_vuln table 
        if unique_vuln in historical_vulnerabilities:
            skipped_duplicate_count += 1
            continue

        # Append vuln to historical vulns 
        elif unique_vuln not in historical_vulnerabilities:

            try: 

                # Extract values with defaults for missing fields
                namespace = vuln.get('namespace', 'Unknown')
                deployment = vuln.get('deployment', 'Unknown')
                imageTag = vuln.get('imageTag', 'Unknown')
                component = vuln.get('component', 'Unknown')
                version = vuln.get('version', 'Unknown')
                cve = vuln.get('cve', 'Unknown')
                cvss = vuln.get('cvss', 'Unknown')
                dateofscan = vuln.get('date_of_scan', "Unknown")
                dateofdiscovery = vuln.get('date_of_discovery', "Unknown")
                state = vuln.get('state', 'Unknown')
                imageHash = vuln.get('imageHash', 'Unknown')
                active = True
                dateOfFix = "NotFixed"  
        
    
                cursor.execute(insert_query, (
                namespace,
                deployment,
                imageTag, 
                component,
                version,
                cve,
                cvss,
                dateofscan,
                dateofdiscovery,
                state,
                imageHash,
                active,
                dateOfFix,
                json.dumps(vuln)  # Store raw JSON data
                ))

                result = cursor.fetchone()
                
                if result:
                    inserted_count += 1
                else:
                    error_list.append(unique_vuln)
                    # skipped_duplicate_count += 1    
                    # print(f"This vulnerability was skipped due to duplication: {vuln}")

            except Exception as e:
                print(f"Error inserting record: {e}")
                print(f"Problematic record: {vuln}")
                skipped_count += 1
                continue


    connection.commit()
    cursor.close()
    
    print(f"Additions to the historical table:")
    print(f"\nSuccessfully inserted: {inserted_count} records")
    print(f"Skipped due to error: {skipped_count} records")
    print(f"Skipped due to duplication: {skipped_duplicate_count} records\n")



def main():
    print(f"""        
         @@@@@@@@@@@@@@@@                                                                                                                                                                    
        @@@@@@@@@@@@@@@@@@                                                                                                                                                                   
        @@@@@@@@@@@@@@@@@@@                                                                                                
       @@ @@@@@@@@@@@@@@@@@                                                                                                
 @@@@@ @@    @@@@@@@@@@@@@@@                                                                                            
@@@@@@@@@@@@     @@@@@@@@@@@                                                                                            
@@@@@@@@ @@@@@@@            @@                                                                                            
 @@@@@@@@@  @@@@@@@@@@@@@@@@@@@@                                                                                           
  @@@@@@@@@@    @@@@@@@@@@@   @@@                
    @@@@@@@@@@@             @@@@@@                                                                                   
       @@@@@@@@@@@@@@@@@@@@@@@@@@                                                                                                                                                            
           @@@@@@@@@@@@@@@@@@@@@                                                                              
              @@@@@@@@@@@@@                                                                                                                                                 
        _    ____ ____     __      _       _                                                                                                                                                
       / \  / ___/ ___|   / _| ___| |_ ___| |__  
      / _ \| |   \___ \  | |_ / _ \ __/ __| '_ \ 
     / ___ \ |___ ___) | |  _|  __/ || (__| | | |
    /_/   \_\____|____/  |_|  \___|\__\___|_| |_|                                                                                                                              
                                                                                                                                                                                                                                                                                                                                            
""")

    print(f"[+] Connecting to ACS and NIST-api to fetch CVE data..")

    # Fetch current data from ACS and sort the relevant data 
    todays_vulnerability_data = []
    for namespace in namespace_list:
        namespace_data = fetch_vulnerability_data(ACS_API_TOKEN, namespace)

        processed_namespace_data = process_vulnerability_data(namespace_data, namespace)
        todays_vulnerability_data.extend(processed_namespace_data)

    print(f"\n[+] Will now update current vulnerabilities...")

    # Connect to the postgres database 
    connection = psycopg2.connect(dbname=dbname, user=user, password=password, host=host, port=port)
    cursor = connection.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id SERIAL PRIMARY KEY,
        namespace VARCHAR(255),
        deployment VARCHAR(255),
        imageTag VARCHAR(255),
        component VARCHAR(255),
        version VARCHAR(255),
        cve VARCHAR(50),
        cvss FLOAT,
        summary TEXT,
        link TEXT,
        fixedBy VARCHAR(255),
        dateofscan TEXT,
        dateofdiscovery TEXT,
        state TEXT,
        imageHash TEXT, 
        deferUrl TEXT,
        raw_data JSONB 
    ); 
    """


    # Create table if it does not already exist 
    cursor.execute(create_table_query)
    connection.commit()

    # Fetch yesterdays scan before we change it.
    yesterdays_vulnerability_data = get_vulnerability_data_postgres(connection, "vulnerabilities")

    # USE WHEN WE WANT TO ADD NEW COLUMNS TO THE DATABASE TABLE - ELSE KEEP COMMENTED! 
    # delete_table = """
    # DROP TABLE vulnerabilities;
    # """
    # cursor.execute(delete_table)
    # connection.commit()



    # Update existing data in table
    truncate_table = """
    TRUNCATE TABLE vulnerabilities RESTART IDENTITY;
    """

    cursor.execute(truncate_table)
    connection.commit()
    # NB consider comment this out.    

    # Check if there exist an uniqueness constraint 
    cursor.execute("""
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'unique_vuln_entry'
        AND conrelid = 'vulnerabilities'::regclass;
    """)

    # If a uniqueness contraint does not exist, add it. 
    exists = cursor.fetchone()
    if not exists:
        add_constraint_query = """
        ALTER TABLE vulnerabilities
        ADD CONSTRAINT unique_vuln_entry
        UNIQUE (namespace, deployment, component, version, cve);
        """

        cursor.execute(add_constraint_query)
        connection.commit()

    insert_vulnerability_data_postgres(connection, todays_vulnerability_data)


    # USE WHEN WE WANT TO ADD NEW COLUMNS TO THE HISTORICAL VULNERABILITIES TABLE - ELSE KEEP COMMENTED! 
    # delete_historical_table = """
    # DROP TABLE historicalVulnerabilities;
    # """

    # cursor.execute(delete_historical_table)
    # connection.commit()


    ### Create long-term CVE database if it does not exists ###
    print(f"==============================\n")
    print(f"\n[+] Will now update the historical vulnerability table...")
    create_longterm_table_query = """
        CREATE TABLE IF NOT EXISTS historicalVulnerabilities (
        id SERIAL PRIMARY KEY,
        namespace VARCHAR(255),
        deployment VARCHAR(255),
        imageTag VARCHAR (255),
        component VARCHAR(255),
        version VARCHAR (255),
        cve VARCHAR(50),
        cvss FLOAT,
        dateofscan TEXT,
        dateofdiscovery TEXT,
        state TEXT,
        imageHash TEXT,
        active BOOLEAN, 
        dateOfFix TEXT,
        raw_data JSONB 
    ); 
    """ 
    cursor.execute(create_longterm_table_query)
    connection.commit()

    # Check if there exist an uniqueness constraint for the historical table 
    cursor.execute("""
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'unique_hist_vuln_entry'
        AND conrelid = 'historicalVulnerabilities'::regclass;
    """)

    # If a uniqueness contraint does not exist, add it. 
    exists = cursor.fetchone()
    if not exists:
        add_constraint_query = """
        ALTER TABLE historicalVulnerabilities
        ADD CONSTRAINT unique_hist_vuln_entry
        UNIQUE (namespace, deployment, component, version, cve);
        """

        cursor.execute(add_constraint_query)
        connection.commit()

    # Check if any vulnerabilities has been fixed since last scan. 
    check_fixed_historical_vulnerabilities(connection, todays_vulnerability_data, yesterdays_vulnerability_data)

    # Append new vulnerabilities that did not exist in the historical table yet. 
    historical_vulnerabilities: list[dict] = get_vulnerability_data_postgres(connection, "historicalVulnerabilities")
    append_vulnerability_data_historical_postgres(connection, todays_vulnerability_data, historical_vulnerabilities)

    print(f"\n[+] run completed.")




if __name__ == "__main__":
    main()

