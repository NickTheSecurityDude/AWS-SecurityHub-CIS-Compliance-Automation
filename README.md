# Automate AWS SecurityHub CIS, PCI and AWS Security Best Practice Compliance

## A new AWS Account is only 39% CIS Compliant by default

![SecurityHub ScreenShot](https://i.postimg.cc/sfQCmgWG/cis-security-hub-initial.png)

This script will help you achieve 100%, or nearly 100%, compliance.

The only manual steup is to setup Hardware MFA for the root user.

![SecurityHub MFA ScreenShot](https://i.postimg.cc/SKJg4JkW/cis-securityhub-hardware-mfa.png)

For this I use a Yubi key and enable U2F hardware MFA in the AWS Console.

![U2F MFA ScreenShot](https://i.postimg.cc/C14B6sXJ/yubi-activate-1.png)

## Running the script

Run the script as follows:

Clone the git repo:
```
git clone https://github.com/NickTheSecurityDude/AWS-SecurityHub-CIS-Compliance-Automation.git
cd AWS-SecurityHub-CIS-Compliance-Automation
```

Enter the following variables in cis-pci-sbp-remediate.py
```
a
```

And run that script, choosing option 0 to run all steps:
```
aws configure sso
python3 cis-pci-sbp-remediate.py
```

