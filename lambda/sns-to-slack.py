#################################################################################################################
#
#  Script: sns-to-slack.py
#  Author: NickTheSecurityDude
#  Created: 08/20/21
#  Updated: 09/03/21
#
#  Description: Lambda function, triggered by SNS, to send CIS Alarm notices to Slack
#
#  Disclaimer: For informational and educational purposes only, not for production use.  CIS
#              requirements are contantly changing, changes to this script and additional
#              steps are necessary.
#
##################################################################################################################

import os
import urllib3
import json
http = urllib3.PoolManager()

def lambda_handler(event, context):

    # for debugging
    print(event)
    
    url_= os.environ['URL']
    
    sub_arn=event['Records'][0]['EventSubscriptionArn']
    
    account=sub_arn.split(":")[4]
    region=sub_arn.split(":")[3]

    # Get the alarm message and alarm name    
    alarm_message=json.loads(event['Records'][0]['Sns']['Message'])
    alarm_name=alarm_message['Trigger']['MetricName']

    # use high severity for all alarms
    severity=7
    
    title=alarm_name
    description=alarm_name
    

    if severity > 6:
      color="#db1f1f"
      symbol=":fire:"
    elif severity >3:
      color="#faa13c"
      symbol=":warning:"
    else:
      color="#f2c744"
      symbol=":question:"
    
    msg_str=symbol+" "+description+"\n"+"Account: "+account+" | Region: "+region+"\n"+"Severity: "+str(severity)+"\n\n"

    # Create a friendly alarm message    
    if title=='CIS-3.1':
      msg_str+="Unauthorized API call"
    if title=='CIS-3.2':
      msg_str+="AWS Management Console sign-in without MFA"
    if title=='CIS-3.2a':
      msg_str+="OK - AWS Management Console sign-in without MFA"
    if title=='CIS-3.3':
      msg_str+="Usage of root account"
    if title=='CIS-3.4':
      msg_str+="IAM policy changes"
    if title=='CIS-3.5':
      msg_str+="CloudTrail configuration change"
    if title=='CIS-3.6':
      msg_str+="AWS Management Console authentication failure"
    if title=='CIS-3.7':
      msg_str+="Customer created CMK disabled or scheduled for deletion"
    if title=='CIS-3.8':
      msg_str+="S3 bucket policy change"
    if title=='CIS-3.9':
      msg_str+="AWS Config configuration change"
    if title=='CIS-3.10':
      msg_str+="Security group change"
    if title=='CIS-3.11':
      msg_str+="NACL Change"
    if title=='CIS-3.12':
      msg_str+="Network Gateway change"
    if title=='CIS-3.13':
      msg_str+="Route table change"
    if title=='CIS-3.14':
      msg_str+="VPC change"
      
    # Debugging info    
    print(msg_str)
    

    # Build message for Slack    
    url = url_
    msg = {
        "channel": "#security-incident-response",
        "icon_emoji": ":red_circle:",
        "text": "CIS Violation Alarm!! "+title,
        "attachments": [{
        "color": color,
        "blocks": [
           {
    	  	 "type": "section",
    		 "text": {
    			"type": "mrkdwn",
    			"text": msg_str
    		 }
    	  }
    	]
      }
    ]
    }
    
    # Send the message to Slack
    encoded_msg = json.dumps(msg).encode('utf-8')
    resp = http.request('POST',url, body=encoded_msg)
    print({
        "message": event, 
        "status_code": resp.status, 
        "response": resp.data
    })

