# acs-fetch

A python script to fetch CVE data from RedHat ACS, and save them in a postgres database.

NOTE: This repo is not activly maintained, consider tweaking code or the Dockerfile to fit your needs.

## Before you start

Before you can run the script you need an ACS api key, which can be generated inside ACS dashboard > Platform Configuration > Integrations > StackRox API Token.
You also should have a NIST api key (free). You can use the NIST api without an api key, but you will get rate limited.
You also need to have a postgresdatabase (obviously).

You can run the script as a normal python script, or you can run it as a container image and run it in docker / kubernetes.

## Setup

1. Setup the required environment variables and script variables (see top of fetch_last_ACS_scan.py)

2. Install the reqired python packages via pip (psycopg2,requests) - recommend to set up a venv for this.

```python
python3 -m venv venv 
```

```python
source .venv/bin/activate
```

```python
pip install -r requirements.txt
```

3.run fetch_last_ACS_scan.py

4.(Optional) Build the pythonscript as a container image, such that it can run in kubernetes.

```shell
docker build -t acs-fetch:tag .
```
