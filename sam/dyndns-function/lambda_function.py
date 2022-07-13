""" Python DYNDNS Handler """
import os  # Required for Environment
from base64 import b64decode  # Required for authentication decoding
import ipaddress  # Required to Check IP Address Validation and types
from botocore.exceptions import ClientError as BotoClientError
import boto3  # Required for AWS DynamoDB and Route53
# DYNDNS API Reference: https://help.dyn.com/remote-access-api/
# GLOBALS
DEFAULT_TTL  = 300
STR_INVUSERPASS = "badauth"
# Boto3 Clients - define outside of function so they persist in Lambda between runs
route53 = boto3.client('route53')
db_client = boto3.client('dynamodb')  # , region_name='us-east-1'

def r53_update(dns_changes):
    """ Perform Update to Route 53 """
    # Check DNS Change receives a success - but don't wait for propogation
    try:
        r53zoneid = get_env('HOSTZONEID')
        response = route53.change_resource_record_sets(
            HostedZoneId=r53zoneid,
            ChangeBatch=dns_changes
        )
        print("INFO: Route53 Status:" + str(response['ChangeInfo']['Status']) +
          " - RequestId: " + str(response['ResponseMetadata']['RequestId']))
        return True
    except BotoClientError:
        print("ERROR: Boto Error: Check HostedZoneId and hostname are correct.")
    return False

def http_exit(res_code, res_text):
    """ Update HTTP Return information for client """
    state = 'INFO' if int(res_code) == 200 else 'ERROR'
    print(str(state) + ": Client Response: "
                + str(res_code) + " - " + str(res_text))
    response = {
        'isBase64Encoded': False,
        'statusCode': int(res_code),
        'headers': {},
        'multiValueHeaders': {},
        'body': str(res_text)
    }
    return response

def get_env(param):
    """ Get environment, checkit and return it or error out """
    if param in os.environ:
        env_param = str(os.environ[param])
    else:
        env_param = False
        print("ERROR: Environment var not found " + str(param))
    return env_param

def authdecode(event):
    """ Authentication decoding - returns user,pass from Base64 Basic Auth """
    username, password = "", ""
    if 'Authorization' in event['headers']:
        authstring = event['headers']['Authorization']
        # Decode the Basic Authentication header
        b64auth = authstring.strip().split(" ")
        if len(b64auth) == 2:  # 'Basic a34d=='
            if b64auth[0] == "Basic":
                try:
                    user, password = b64decode(b64auth[1]).decode().split(':', 1)
                    print("INFO: Authentication Header is valid")
                    if user.isalnum():
                        username = user
                # pylint: disable=W0702
                except:
                    print("ERROR: Unable to decode Basic Authentication")
            else:
                print ("Not Basic Auth")
    return str(username), str(password)

def check_ipver(check_ip,ip_ver):
    """ Check IP address is correct version before further processing """
    try:
        ip_addr = ipaddress.ip_address(check_ip)
        if int(ipaddress.ip_address(check_ip).version) == int(ip_ver):
            return ip_addr
    except ValueError:
        pass
    return False

def get_ip(event,ip_ver):
    """ Check if IP address has been passed on URI """
    ip_addr = False
    my_ip = False
    if 'queryStringParameters' in event:
        qparams = event['queryStringParameters']
        if qparams is not None:
            if 'myip' in qparams:
                ip_addr = check_ipver(qparams['myip'],ip_ver)
                my_ip = True
                if ip_addr:
                    print("INFO: Using URI Provided myip IPv" + str(ip_ver) + ":" + str(ip_addr))
    # Only process headers if no 'myip' param
    if not ip_addr and not my_ip:
        ip_header = str(event['headers']['X-Forwarded-For'])
        ip_addr = check_ipver(ip_header, ip_ver)
        if ip_addr:
            print("INFO: Using Header X-Forwarded-For for IPv" + str(ip_ver) + ":" + str(ip_addr))
    if not ip_addr:
        print("INFO: Unable to determine an IPv" + str(ip_ver) + " address")
    return ip_addr

def set_ttl(host_db):
    """ Set Default TTL if there is no TTL field in the DB for the user """
    if 'ttl' in host_db:
        ttl = int(host_db['ttl']['S'])
    else:
        ttl = DEFAULT_TTL
    return ttl

def add_r53_change(host, value, ttl):
    """ Create JSON payload to pass to Route53 Update """
    if int(ipaddress.ip_address(value).version) == 4:
        r_type = 'A'
    elif int(ipaddress.ip_address(value).version) == 6:
        r_type = 'AAAA'
    dns_changes = {
      'Action': 'UPSERT',
      'ResourceRecordSet': {
        'Type': r_type,
        'Name': host,
        'TTL': ttl,
        'ResourceRecords': [ { 'Value': str(value) } ]
      }
    }
    print("INFO: Will Update " + host + " " + r_type + " " + str(value) + " TTL:" + str(ttl))
    return dns_changes

def get_clientinfo(event):
    """ Get Basic info about our client """
    if 'User-Agent' in event['headers']:
        user_agent = " User Agent:" + str(event['headers']['User-Agent'])
    else:
        user_agent = ""
    print( "INFO: Request Received from:"
        + str(event['headers']['X-Forwarded-For']) + user_agent)
    

def handler(event, context):  # pylint: disable=W0613
    """ Main function """
    # print("params: " + str(event['queryStringParameters']))
    dns_changes = { 'Changes': [] }
    db_user, db_pass = "", ""  # Define to prevent errors
    try:
        get_clientinfo(event)
        # Get auth from Headers
        q_user, q_pass = authdecode(event)
        # Lookup user in DynamoDB, return record
        print("INFO: Looking for user " + str(q_user))
        dbtablename = get_env('DBNAME')
        host_db = db_client.get_item(
            TableName=dbtablename,
            Key={'user': {'S':q_user}}
        )
        # If a User Record is returned
        if 'Item' in host_db:
            db_user = str(host_db['Item']['user']['S'])
            db_pass = str(host_db['Item']['pass']['S'])
            db_host = str(host_db['Item']['host']['S'])
            ttl = set_ttl(host_db['Item'])
        # If password matches, process the record
        if db_user == q_user and db_pass == q_pass and len(q_user) >= 3 and len(q_pass) >= 8:
            # Handle DB results - Item will not exist if user key was not found
            print("INFO: User Authentication successful")
            ipv4 = get_ip(event,4)
            if ipv4:  # If there is an IPv4 address set - add the change record
                dns_changes['Changes'].append(add_r53_change(db_host, ipv4, ttl))
            ipv6 = get_ip(event,6)
            if ipv6:  # If there is an IPv6 address set - add the change record
                dns_changes['Changes'].append(add_r53_change(db_host, ipv6, ttl))
            if r53_update(dns_changes):
                if ipv4:
                    response = http_exit(200,"good " +str(ipv4))
                if ipv6:
                    response = http_exit(200,"good " +str(ipv6))
                print("INFO: Update Successful")
        elif len(db_user) == 0:
            print("ERROR: User " + str(q_user) + " not found")
            response = http_exit(403,STR_INVUSERPASS)
        elif len(db_user) < 3 or len(q_pass) < 8:
            print("ERROR: Username or password too short")
            response = http_exit(403,STR_INVUSERPASS)
        else:
            print("ERROR: Password incorrect")
            response = http_exit(403,STR_INVUSERPASS)
    except Exception as error: # pylint: disable=broad-except
        response = http_exit(500,"911")  # Default to a 911 Error (Dyndns)
        print("ERROR: Exception: " + str(error))
    return response
