import socket
import ssl
import datetime
import sys

help_text = """

Usage:
python verify-certificate.py <domain Name> 
EXAMPLE: python verify-certificate.py www.hua.gr 
OR with multiple domains: python verify-certificate www.hua.gr www.google.com

"""
try:
    sys.argv[1]
except IndexError:
    print help_text
    exit(0)

# A list with all domains given from user's input
domains_url = sys.argv[1:]

# A list with trusted issuers
allTrustedIssuers = [
  "TERENA SSL CA 3",
  "Let's Encrypt",
  "Comodo",
  "Symantec",
  "GeoTrust",
  "GTS CA 1O1",
  "DigiCert SHA2 High Assurance Server CA"
]

# A function which gets info about the certificate using web socket and ssl
def get_certificate(hostname):

    context = ssl.create_default_context()
    context.check_hostname = False
    conn = context.wrap_socket(socket.socket(socket.AF_INET),server_hostname=hostname)
    # 5 second timeout
    conn.settimeout(5.0)
    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()

    return ssl_info

# A function which returns a datetime object in a specific format
def ssl_expiry_datetime(ssl_info):

    ssl_dateformat = r'%b %d %H:%M:%S %Y %Z'

    # Python datetime object
    return datetime.datetime.strptime(ssl_info['notAfter'], ssl_dateformat)

# A function which verifies if the issuer of the certificate belongs to a trusted list
def check_issuer(hostname):

    issuer = dict(x[0] for x in ssl_info['issuer'])
    issued_by = issuer['commonName']
    isTrustedIssuer = False
    for issuerName in allTrustedIssuers:
      if issued_by == issuerName:
        isTrustedIssuer = True
        break
    if isTrustedIssuer:
       print ("The issuer {} for the following domain is trusted:".format(issuerName))
    else:
       print ("The issuer for the following domain doesn't belong in trusted issuer's list:")

#Verifying the host matches the common name on the certificate
def validate_domain(hostname):
    import re
    subject = dict(x[0] for x in ssl_info['subject'])
    common_name = subject['commonName']
    print common_name
    regex = common_name.replace('.', r'\.').replace('*',r'.*') + '$'
    if re.match(regex, hostname):
        print ("Success! The host name: {} matches to the common name on the certificate.".format(hostname))
    else:
        print ("Warning! The host name: {} doesn't match to the common name on the certificate.".format(hostname))

#Verifying the version of the certificates
def check_version(hostname):
    version = ssl_info['version']
    print ("Certificate's version is: {}".format(version))

if __name__ == "__main__":
    for value in domains_url:
        now = datetime.datetime.now()
        try:
            ssl_info = get_certificate(value)
            issuer_info = check_issuer(value)
            expire = ssl_expiry_datetime(ssl_info)
            validateDomainName = validate_domain(value)
            diff = expire - now
            print ("Expiry Date: {} Expiry Day: {}".format(expire.strftime("%Y-%m-%d"),diff.days))
            version_info = check_version(value)
        except Exception as e:
            print (e)
