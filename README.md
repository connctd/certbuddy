# certbuddy

certbuddy is a small utility to ensure that your certificate issued by letsencrypt (or another
automated CA) stays up to date.
This utility is implemented as a small daemon running in the background. On startup certbuddy
creates an account for you if necessary and generates privates keys etc. It then requests a
certificate and checks in regular intervals if this certificate is still valid. If it is about
to expire certbuddy tries to renew your certificate.

Ideally certbuddy can be used in Docker container to update a certificate used for your servers 
providing TLS termination.

## Usage

certbuddy has several command line switches, but only some are necessary

### Command line switches

Name | Description | Required | Default
---- | ----------- | -------- | -------
email | Email address of the user account for letsencrypt | Yes | None
domains | Comma separated list of domains to be included in the certificate | Yes | None
keyPath | Path to the private key used for the TLS certificate | Yes | None
certPath | Path to the TLS certificate issued by letsencrypt | Yes | None
renewBefore | Number of days before the expiration date when certificate will be renewed | No | 30
webroot | Folder to write the proof to. Needs to be accessible by a webserver | Yes | None
accountKeyPath | Path to the private key for the letsencrypt account | Yes | None
rsaLength | Length of the RSA key | No | 4096
