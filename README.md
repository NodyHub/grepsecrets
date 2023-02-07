# grepsecrets
Grep Secrets from input


## Installation


```shell
$ go install github.com/NodyHub/fifi@latest

```
Or download latest release manual [here](https://github.com/NodyHub/grepsecrets/releases).

## Usage

```shell
$ grepsecrets -h
usage: grepsecrets [flags] [files]
grepsecrets searches for secrets in provided input.

Default reads from stdin

Options:
--------
[files] provide the files.
  -l	List patterns
  -v	Verbose output

github.com/NodyHub/grepsecrets@(devel) 2023-02-07T11:02:43Z
```

## Current list of secrets & patterns

```shell
$ grepsecrets -l
Facebook Access Token: "EAACEdEose0cBA[0-9A-Za-z]+"
Google (GCP) Service-account: "\"type\": \"service_account\""
Heroku API Key: "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"
Password in URL: "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"
Twitter OAuth: "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
Google OAuth Access Token: "ya29\\.[0-9A-Za-z\\-_]+"
Square OAuth Secret: "sq0csp-[0-9A-Za-z\\-_]{43}"
Twitter Access Token: "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}"
Mailgun API Key: "key-[0-9a-zA-Z]{32}"
Firebase URL: ".*firebaseio\.com"
SSH (DSA) private key: "-----BEGIN DSA PRIVATE KEY-----"
Amazon AWS Access Key ID: "AKIA[0-9A-Z]{16}"
AWS API Key: "AKIA[0-9A-Z]{16}"
Generic API Key: "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]"
Google Drive OAuth: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
Google Gmail OAuth: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
Slack Webhook: "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
PGP private key block: "-----BEGIN PGP PRIVATE KEY BLOCK-----"
Picatic API Key: "sk_live_[0-9a-z]{32}"
Stripe API Key: "sk_live_[0-9a-zA-Z]{24}"
Square Access Token: "sq0atp-[0-9A-Za-z\\-_]{22}"
Slack Token: "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"
PayPal Braintree Access Token: "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"
SSH (EC) private key: "-----BEGIN EC PRIVATE KEY-----"
Amazon MWS Auth Token: "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
Generic Secret: "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]"
Google Cloud Platform OAuth: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
MailChimp API Key: "[0-9a-f]{32}-us[0-9]{1,2}"
Twilio API Key: "SK[0-9a-fA-F]{32}"
RSA private key: "-----BEGIN RSA PRIVATE KEY-----"
Facebook OAuth: "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]"
Google Cloud Platform API Key: "AIza[0-9A-Za-z\\-_]{35}"
Google YouTube API Key: "AIza[0-9A-Za-z\\-_]{35}"
Stripe Restricted API Key: "rk_live_[0-9a-zA-Z]{24}"
Cloudinary: "cloudinary://.*"
Open SSH Private Key: "-----BEGIN OPENSSH PRIVATE KEY-----"
GitHub: "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]"
Google API Key: "AIza[0-9A-Za-z\\-_]{35}"
Google Drive API Key: "AIza[0-9A-Za-z\\-_]{35}"
Google Gmail API Key: "AIza[0-9A-Za-z\\-_]{35}"
Google YouTube OAuth: "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"
```