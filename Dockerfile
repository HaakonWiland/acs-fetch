ARG PIP_VERSION=25.3

## BUILD STAGE ##
FROM python:3.13-slim AS build

ARG PIP_VERSION
RUN python -m pip install --upgrade "pip==${PIP_VERSION}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev  ca-certificates \ 
    && rm -rf /var/lib/apt/lists/*

RUN pip install --user requests psycopg2

## RUNTIME STAGE ##  
FROM python:3.13-slim

ARG PIP_VERSION
RUN python -m pip install --upgrade "pip==${PIP_VERSION}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 ca-certificates \ 
    && rm -rf /var/lib/apt/lists/*. 

# Create a non-root user and group
RUN useradd -u 10001 -m appuser

# Copy libs and script 
COPY --from=build /root/.local /usr/local
WORKDIR /usr/src/app
COPY fetch_last_ACS_scan.py .

# Give ownership to the non-root user
RUN chown -R appuser:appuser /usr/src/app /usr/local

# Switch to non-root
USER 10001

CMD ["python", "fetch_last_ACS_scan.py"]