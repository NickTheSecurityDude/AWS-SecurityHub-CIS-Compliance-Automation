######################################################################################################
#
#  Script: cis-pci-sbp-remediate.py
#  Author: NickTheSecurityDude
#  Created: 08/20/21
#  Updated: 08/20/21
#
#  Description: Helps automate the CIS compliance checks in SecurityHub
#
#  Prerequisistes: 1. Enable MFA for root account
#                  2. Upload templates folder to s3 bucket
#
#  Recommendations: Setup accounts using Account Factory in Control Tower with no VPCs enabled
#
#  Instructions: 1. Enter the variables below
#                2. Assume a role which can assume a cross account admin role in the GuardDuty
#                   main account and target accounts
#
#  Disclaimer: For informational and educational purposes only, not for production use.  CIS
#              requirements are contantly changing, changes to this script and additional 
#              steps are necessary.
#
######################################################################################################

import boto3,json,time

#Required Variables

# Account you are making CIS Compliant and its contact email
target_acct=""
target_email=""

# your GuardDuty Account and its Detector ID
gd_main_acct=""
gd_main_acct_detector_id=""

# Cross account role, if you're using ControlTower, you shouldn't need to change this
admin_role="AWSControlTowerExecution"

# S3 bucket where you uploaded the templates/ folder
s3_template_bucket=""

s3_sub_folder="templates"

pLogGroupName="CIS-Metric-Filters"
pMetricNamespace="LogMetrics"
pSNSAlarmTopicName="CIS-Topic"

sts_client = boto3.client('sts')
region=sts_client.meta.region_name

s3_template_bucket_url="s3."+region+".amazonaws.com/"+s3_template_bucket

# Assume Cross Account Role Function
def assumed_role_session(arn,ext_id=None):
  credentials = sts_client.assume_role(
    RoleArn=arn,
    RoleSessionName='role1-session',
    #ExternalId=ext_id
  )['Credentials']

  aws_access_key_id = credentials['AccessKeyId']
  aws_secret_access_key = credentials['SecretAccessKey']
  aws_session_token = credentials['SessionToken']

  return boto3.session.Session(
           aws_access_key_id=aws_access_key_id,
           aws_secret_access_key=aws_secret_access_key,
           aws_session_token=aws_session_token
         )

# target
session_target=assumed_role_session('arn:aws:iam::'+target_acct+':role/'+admin_role)
session_target_ec2 = session_target.client('ec2')
session_target_gd=session_target.client('guardduty')
session_target_ec2_res = session_target.resource('ec2')
session_target_iam = session_target.client('iam')
session_target_lambda = session_target.client('lambda')
session_target_ssm = session_target.client('ssm')
session_target_s3 = session_target.client('s3')
session_target_sh = session_target.client('securityhub')
session_target_cf = session_target.client('cloudformation')

# guardduty main
session_gd_main=assumed_role_session('arn:aws:iam::'+gd_main_acct+':role/'+admin_role)
session_gd_main_gd=session_gd_main.client('guardduty')

# Step 1
def launch_cloudformation(stack_name,pLogGroupName,pMetricNamespace,pSNSAlarmTopicName,s3_template_bucket,s3_sub_folder):

  print("Creating CloudFormation Nested Stack")

  response = session_target_cf.create_stack(
    StackName=stack_name,
    TemplateURL='https://'+s3_template_bucket_url+'/'+s3_sub_folder+'/cis-remediate-ROOT.yaml',
    Capabilities=['CAPABILITY_NAMED_IAM'],
    Parameters=[
      {
        'ParameterKey': 'pLogGroupName',
        'ParameterValue': pLogGroupName
      },
      {
        'ParameterKey': 'pMetricNamespace',
        'ParameterValue': pMetricNamespace
      },
      {
        'ParameterKey': 'pSNSAlarmTopicName',
        'ParameterValue': pSNSAlarmTopicName
      },
      {
        'ParameterKey': 'pS3Bucket',
        'ParameterValue': s3_template_bucket
      },
      {
        'ParameterKey': 'pS3Prefix',
        'ParameterValue': s3_sub_folder
      }
    ],
    DisableRollback=True
  )
  print(response)

  return 1

# Step 2
def enable_guardduty():

  print("Create GuardDuty Detector in Target Account")

  #Target Account
  response=session_target_gd.create_detector(
           Enable=True
         )
  print(response)

  target_acct_detector_id=response['DetectorId']

  print("Create GuardDuty member in GuardDuty Main Account")

  #Central Account
  response=session_gd_main_gd.create_members(
           DetectorId=gd_main_acct_detector_id,
           AccountDetails=[
             {
               'AccountId': target_acct,
               'Email': target_email
             }
           ]
         )
  print(response)

  print("Invite GuardDuty member in GuardDuty Main Account")

  response=session_gd_main_gd.invite_members(
           DetectorId=gd_main_acct_detector_id,
           AccountIds=[target_acct],
           DisableEmailNotification=True
         )
  print(response)

  print("Sleep 60 seconds so invite can arrive")
  time.sleep(60)

  print("Accpet GuardDuty invitation in Target Account")

  #Target Account
  response=session_target_gd.list_invitations()
  invitation_id=response['Invitations'][0]['InvitationId']

  response = session_target_gd.accept_invitation(
    DetectorId=target_acct_detector_id,
    MasterId=gd_main_acct,
    InvitationId=invitation_id
  )
  print(response)

  print("GuardDuty Enabled")

  return 1

# Step 3
def remove_default_sg_rules():

  print("Get Default Security Group")

  response = session_target_ec2.describe_security_groups(
    Filters=[
      {
        'Name': 'group-name',
        'Values': ['default']
      }
    ]
  )

  groups=response['SecurityGroups']
  for group in groups:
    group_id=group['GroupId']

    response = session_target_ec2.describe_security_group_rules(
      Filters=[
        {
          'Name': 'group-id',
          'Values': [group_id]
        }
      ],
      MaxResults=1000
    )  
 
    print("Remove rules from Default Security Group")

    rules=response['SecurityGroupRules']
    for rule in rules:
      rule_id=rule['SecurityGroupRuleId']
      is_egress=rule['IsEgress']

      security_group = session_target_ec2_res.SecurityGroup(group_id)

      if is_egress:
        response = security_group.revoke_egress(
          SecurityGroupRuleIds=[rule_id]  
        )
      else:
        response = security_group.revoke_ingress(
          SecurityGroupRuleIds=[rule_id]
        )

      print(response['ResponseMetadata']['HTTPStatusCode'])

  print("Default Security Group Rules removed")

  return 1

# Step 4
def update_password_policy():
  
  print("Update IAM Password Policy")

  response = session_target_iam.update_account_password_policy(
    MinimumPasswordLength=14,
    RequireSymbols=True,
    RequireNumbers=True,
    RequireUppercaseCharacters=True,
    RequireLowercaseCharacters=True,
    AllowUsersToChangePassword=True,
    MaxPasswordAge=90,
    PasswordReusePrevention=24
  )

  print("IAM Password Policy Updated")

  return 1

# Step 5
def s3_force_secure_transport():

  print("Get all buckets")

  response = session_target_s3.list_buckets()
  buckets=response['Buckets']

  for bucket in buckets:
    #print(bucket)
    bucket_name=bucket['Name']

    secure_transport_sid={
      "Sid": "AllowSSLRequestsOnly",
      "Action": "s3:*",
      "Effect": "Deny",
      "Resource": [
        "arn:aws:s3:::"+bucket_name,
        "arn:aws:s3:::"+bucket_name+"/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      },
      "Principal": "*"
    }

    #print(secure_transport_sid)

    sids=[]

    try:
      response = session_target_s3.get_bucket_policy(
        Bucket=bucket_name
      )
      sids=json.loads(response['Policy'])['Statement']
    except:
      pass

    print("Add force secure transport sid to bucket")

    sids.append(secure_transport_sid)
    bucket_policy={
      "Version": "2012-10-17",
      "Statement": sids
    }

    #print(bucket_policy) 

    print("Update bucket policy")

    response = session_target_s3.put_bucket_policy(
      Bucket=bucket_name,
      Policy=json.dumps(bucket_policy)
    )

    print(response['ResponseMetadata']['HTTPStatusCode']) 

  print("Secure Transport required enabled on all buckets")

  return 1

# Step 6
def enable_pci_standard():

  print("Enabling PCI standards for SecurityHub")

  arn_to_enable="arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"

  response = session_target_sh.batch_enable_standards(
    StandardsSubscriptionRequests=[
      {
        'StandardsArn': arn_to_enable,
      },
    ]
  )

  print(response)

  print("PCI standards for SecurityHub Enabled")

  return 1

# Step 7
def disable_s3_crr():

  print("Disable SecurityHub PCI Rule for Cross Region Replication required")

  arn_to_disable="arn:aws:securityhub:"+region+":"+target_acct+":control/pci-dss/v/3.2.1/PCI.S3.3"

  response = session_target_sh.update_standards_control(
    StandardsControlArn=arn_to_disable,
    ControlStatus='DISABLED',
    DisabledReason='Not needed per resiliancy pattern.'
  )

  print(response)

  print("SecurityHub PCI Rule for Cross Region Replication required disabled")

  return 1

# Step 8
def vpc_for_controltower_lambda():

  controltower_vpc_id=0
  ctv_found=0

  print("Attaching VPC Access Execution Role to Lambda function")

  response = session_target_iam.attach_role_policy(
    RoleName='aws-controltower-ForwardSnsNotificationRole',
    PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole'
  )
  print(response)
  print("Wait 60 seconds for policy to become active")
  time.sleep(60)

  print("Get VPCs")

  response = session_target_ec2.describe_vpcs()
  vpcs=response['Vpcs']
  for vpc in vpcs:
    vpc_id=vpc['VpcId']
    for tag in vpc['Tags']:
      if tag['Value'] == 'LambdaCTVPC':
        controltower_vpc_id=vpc_id
        ctv_found=1

  if ctv_found==1:
    print("Lambda CT VPC Found")


    print("Get subnets")

    response = session_target_ec2.describe_subnets(
      Filters=[
        {
          'Name': 'vpc-id',
          'Values': [controltower_vpc_id]
        }
      ]
    )
    #print(response)

    vpc_subnets=[]

    subnets=response['Subnets']
    for subnet in subnets:
      vpc_subnets.append(subnet['SubnetId'])


    print(vpc_subnets)

    print("Get Lambda Security Group from SSM")

    #get lambda sg ssm
    response = session_target_ssm.get_parameter(
      Name='/security-group/lambda/controltower'
    )

    print(response['Parameter']['Value'])
    security_group_id=response['Parameter']['Value']

    lambda_arn='arn:aws:lambda:'+region+':'+target_acct+':function:aws-controltower-NotificationForwarder'
    print(lambda_arn)

    print("Update lambda function configuration")
 
    response = session_target_lambda.update_function_configuration(
      FunctionName=lambda_arn,
      VpcConfig={
        'SubnetIds': vpc_subnets,
        'SecurityGroupIds': [security_group_id]
      }
    )

  print("Lambda function VPC access enabled")

  return 1


##################################
  Begin main code
##################################

# Display Menu
menu = {}
menu['0']="All Steps"
menu['1']="Step 1: Launch CloudFormation Stack"
menu['2']="Step 2: Enable GuardDuty"
menu['3']="Step 3: Remove Default Security Group Rules"
menu['4']="Step 4: Update Password Policy"
menu['5']="Step 5: Enable S3 Secure Transport"
menu['6']="Step 6: Enable PCI Standards"
menu['7']="Step 7: Disable CRR Rule"
menu['8']="Step 8: Enable VPC for Control Tower Lambda"
menu['9']="Exit"

# Loop for menu
while True:

  options=menu.keys()

  for entry in options:
    print(entry, menu[entry])

  selection=int(input("Please Select: "))

  # If 0, then perform all steps
  if selection==0:
    print("Performing all steps")

  if selection==1 or selection==0:
    print("Step 1: Launching CloudFormation Stack")
    stack_name="CIS-Remediate"
    launch_cloudformation(stack_name,pLogGroupName,pMetricNamespace,pSNSAlarmTopicName,s3_template_bucket,s3_sub_folder)
    print("Waiting for CF Stack")

    # waiter for CloudFormation stack
    waiter = session_target_cf.get_waiter('stack_create_complete')
    waiter.wait(
      StackName=stack_name,
      WaiterConfig={
        'Delay': 60,
        'MaxAttempts': 30
      }
    )
    print("CloudFormation stack created.")

  if selection==2 or selection==0:
    print("Step 2: Enabling GuardDuty")
    enable_guardduty()

  if selection==3 or selection==0:
    print("Step 3: Removing default Security Group Rules")
    remove_default_sg_rules()

  if selection==4 or selection==0:
    print("Step 4: Updating Password Policy")
    update_password_policy()

  if selection==5 or selection==0:
    print("Step 5: Enabling S3 Secure Transport")
    s3_force_secure_transport()

  if selection==6 or selection==0:
    print("Step 6: Enable PCI Standards")
    enable_pci_standard()
    print("Waiting 1 minute for PCI standards to be enabled")
    time.sleep(60)

  if selection==7 or selection==0:
    print("Step 7: Disable CRR Rule")
    disable_s3_crr()

  if selection==8 or selection==0:
    print("Step 8: Enable VPC for Control Tower Lambda")
    vpc_for_controltower_lambda()

  if selection==0 or selection==9:
    print("Exiting...")
    break 

  if not (selection >=0 and selection <=9):
    print("Unknown Option Selected!")
