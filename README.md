# monitoring-check_certificate
a simple nagios check that connects to a https port and checks the certificate expiry date
## Installation
just copy and make sure you have `nagiospluin`installed. E.g.
```
pip install nagiosplugin
```
or apt-get, yum, ...
```
./check_certificates.py -h
Usage: check_certificate.py [options]

Options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain=DOMAIN
                        check certificate of DOMAIN
  -p PORT, --port=PORT  destination PORT
  -t TIMEOUT, --timeout=TIMEOUT
                        set connection timeout to TIMEOUT
  -w WARN, --warning=WARN
                        warn if certificate is expiring in less than WARN
                        seconds
  -c CRITICAL, --critical=CRITICAL
                        critical if certificate is expiring in less than
                        CRITICAL seconds
  -v, --verbose         verbose output
```