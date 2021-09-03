# Automate AWS SecurityHub CIS, PCI and AWS Security Best Practice Compliance

## A new AWS Account is only 39% CIS Compliant by default

![SecurityHub ScreenShot](https://i.postimg.cc/sfQCmgWG/cis-security-hub-initial.png)

This script will help you achieve 100%, or nearly 100%, compliance.

The only manual steup is to setup Hardware MFA for the root user.

![SecurityHub MFA ScreenShot](https://i.postimg.cc/SKJg4JkW/cis-securityhub-hardware-mfa.png)

For this I use a Yubi key and enable U2F hardware MFA in the AWS Console.

![U2F MFA ScreenShot](https://i.postimg.cc/C14B6sXJ/yubi-activate-1.png)

This will script will trigger CloudWatch Alarms for CIS violations, which will then send an email alert, as well as an alert to Slack.

![CIS Slack ScreenShot](https://i.postimg.cc/rphnv3bY/cis-slack.png)

## Running the script

```
######################################################################################################################
#
#  Script: cis-pci-sbp-remediate.py
#  Author: NickTheSecurityDude
#  Created: 08/20/21
#  Updated: 09/03/21
#
#  Description: Helps automate the CIS, PCI and AWS Security Best Practice compliance checks in SecurityHub
#
#  Prerequisistes: 1. Enable MFA for root account
#                  2. Upload the templates and lambda folders to s3 bucket
#                  3. Create a Slack channel named: security-incident-response
#                     and create a Slack web hook
#
#  Recommendations: Setup accounts using Account Factory in Control Tower with no VPCs enabled
#
#  Instructions: 1. Enter the variables below
#                2. Assume a role which can assume a cross account admin role in the GuardDuty
#                   main account and target accounts
#                3. This script can be run step by step or it can run all steps at once (option 0)
#                DO NOT RUN THE CLOUDFORMATION STACK DIRECTLY, THIS SCRIPT WILL RUN IT
#
#  Notes: Occassionally and update by AWS to config rules will trigger false positive alarms.  For example
#         while developing this AWS released a fix deployment for Lambda.2, which swapped the underlying configRule,
#         which resulted in SecurityHub getting an access denied message for the config
#         rule: lambda-function-settings-check*
#         No action is necessary to remediate these as they will fix themselves within 24 hours.
#
#  Disclaimer: For informational and educational purposes only, not for production use.  CIS
#              requirements are contantly changing, changes to this script and additional
#              steps are necessary.  This script launches AWS resources which may not be included in their free tier.
#
#######################################################################################################################
```

Run the script as follows:

Clone the git repo:
```
git clone https://github.com/NickTheSecurityDude/AWS-SecurityHub-CIS-Compliance-Automation.git
cd AWS-SecurityHub-CIS-Compliance-Automation
```

Upload the templates and lambda folders to your S3 bucket.

Enter the following variables in cis-pci-sbp-remediate.py
```
#Required Variables

# Target Account = Account to make CIS compliant
target_acct=""

# Email of target account
target_email=""

# Email you want to use for SNS topics
sns_email=""

# Account ID of your GuardDuty Account, as well as the detector ID
gd_main_acct=""
gd_main_acct_detector_id=""

# Admin role, if you use Control Tower you can use AWSControlTowerExecution
admin_role="AWSControlTowerExecution"

# Required CloudFormation Variables
# Camel case used for CF variable names to match CloudFormation variable naming convention
pS3Bucket=""
pLambdaBucket=""
pMasterAcct=""
pOrgId=""
pSlackWebHook=""
```

I recommond connecting to the CLI using SSO and selecting a user which can assume the admin_role you set above in the required accounts.

![AWS CLI SSO ScreenShot](https://i.postimg.cc/1RpmZKmr/cis-cli-sso.png)

This script has been tested in us-east-1.

And run the script, choosing option 0 to run all steps:
```
aws configure sso
export AWS_PROFILE=your_profile_name
aws sts get-caller-identity
python3 cis-pci-sbp-remediate.py
```

![All Steps ScreenShot](https://i.postimg.cc/XJbPKdRn/cis-allsteps-0.png)

The script will take about 15-20 minutes to complete.

You will see output similar to this:
```
Performing all steps
Step 1: Launching CloudFormation Stack
Waiting for CF Stack
...
Step 2: Enabling GuardDuty
...
Step 3: Removing default Security Group Rules
200
200
Step 4: Updating Password Policy
Step 5: Enabling S3 Secure Transport
204
204
204
Step 6: Enable PCI Standards
...
Waiting 1 minute for PCI standards to be enabled
Step 7: Disable CRR Rule
...
Step 8: Enable VPC for Control Tower Lambda
Wait 60 seconds for policy to become active
Lambda CT VPC Found
Successful
Exiting...
```

Remember to confirm the SNS email subscription.

SecurityHub will take 24 hours to update, however after a few hours if you click on the individual controls they should show as Passed/Compliant.
