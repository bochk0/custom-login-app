![1000009729](https://github.com/user-attachments/assets/190c3c61-da38-44b4-b408-474f6a103377)
![1000009730](https://github.com/user-attachments/assets/56969f23-0fdd-406e-8912-e8b92557bddb)
![1000009731](https://github.com/user-attachments/assets/848da9b8-cfce-4452-a683-b29200907ed4)
![1000009732](https://github.com/user-attachments/assets/79f8b9ff-7473-4d10-8def-bb937a5e06aa)
![1000009734](https://github.com/user-attachments/assets/e0532806-b1d1-43a8-8216-530973d93059)



# Self-Hosting Guide

Ensure your online identity remains private by managing your own email server. This guide provides detailed steps to set up and run your own email instance. Follow the instructions below to get started.

## Overview

By hosting your own email instance, you gain control over your online identity and reduce the risk of being tracked through a common email address.

## Prerequisites

### Hardware Requirements

- A Linux server (VM or dedicated), preferably with at least 2 GB of RAM.
### Software Requirements

- A domain name for configuring DNS
- Ubuntu
- Docker

## Initial Setup

### Install Utilities

First, update your package list and install necessary utilities:

```bash
sudo apt update && sudo apt install -y dnsutils
```

### Create Directories for Data Storage

Create directories to store data:

```bash
mkdir -p sl/pgp sl/db sl/upload
```

## Configuring DNS

### MX Record

Create an MX record for your domain to direct email traffic:

```bash
dig @1.1.1.1 domain.com mx
```

Expected output:

```
domain.com. 3600 IN MX 10 app.domain.com.
```

### A Record

Create an A record to point your subdomain to your server's IP address:

```bash
dig @1.1.1.1 app.domain.com a
```

Expected output should be your server's IP address.

### Setting Up DKIM

Generate DKIM keys:

```bash
openssl genrsa -out dkim.key -traditional 1024
openssl rsa -in dkim.key -pubout -out dkim.pub.key
```

Add a TXT record for DKIM:

```plaintext
v=DKIM1; k=rsa; p=PUBLIC_KEY
```

Replace `PUBLIC_KEY` with your public key, formatted as a single line.

Verify DKIM setup:

```bash
dig @1.1.1.1 dkim._domainkey.domain.com txt
```

### Setting Up SPF

Add a TXT record for SPF:

```plaintext
v=spf1 mx ~all
```

Verify SPF setup:

```bash
dig @1.1.1.1 domain.com txt
```

### Setting Up DMARC

Add a TXT record for DMARC:

```plaintext
v=DMARC1; p=quarantine; adkim=r; aspf=r
```

Verify DMARC setup:

```bash
dig @1.1.1.1 _dmarc.domain.com txt
```

## Docker Setup

### Install Docker

Install Docker using the following script:

```bash
curl -fsSL https://get.docker.com | sh
```

### Create Docker Network

Create a Docker network for your containers:

```bash
sudo docker network create -d bridge \
    --subnet=10.0.0.0/24 \
    --gateway=10.0.0.1 \
    sl-network
```
