# veeam-inventory-api

I started this testing to hopefully use this either as a standalone tool or in another project of mine. 

This will require a Veeam Backup & Replication Build Version: 12.2.0.334 (tested version) with API enabled and service running. 

You can run and build this using Golang locally 

When you first run you can either define some environment variables or it will prompt you for details when ran 

## Setting Environment Variables 

Linux 
```
export VBR_SERVER_URL="https://<VBR_Server>:9419/api/v1"
export VBR_USERNAME="your_username"
export VBR_PASSWORD="your_password"
```
Windows Command Line 
```
set VBR_SERVER_URL=https://<VBR_Server>:9419
set VBR_USERNAME=your_username
set VBR_PASSWORD=your_password
```

Windows PowerShell 
```
$env:VBR_SERVER_URL="https://<VBR_Server>:9419"
$env:VBR_USERNAME="your_username"
$env:VBR_PASSWORD="your_password"
```

## Troubleshooting access to Veeam API 

I am in a test environment so you will see in my curl commands `-k` is used. 

Get access token with 

```
curl -k -X 'POST' \
  'https://192.168.169.185:9419/api/oauth2/token' \
  -H 'accept: application/json' \
  -H 'x-api-version: 1.1-rev2' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=Administrator&password=Passw0rd999!&refresh_token=&code=&use_short_term_refresh=&vbr_token=' \
  | jq -r '.access_token'
```

By then taking the access_token output from the above command you can add this to the Bearer

```
curl -k -X 'GET' \
  'https://192.168.169.185:9419/api/v1/jobs' \
  -H 'accept: application/json' \
  -H 'x-api-version: 1.1-rev2' \
  -H 'Authorization: Bearer <PASTE ABOVE OUTPUT>'
```



