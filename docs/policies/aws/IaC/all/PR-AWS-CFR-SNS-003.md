



# Title: AWS SNS topic with server-side encryption disabled


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-SNS-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-SNS-003|
|eval|data.rule.sns_encrypt|
|message|data.rule.sns_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sns-subscription.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_SNS_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** This policy identifies Amazon Simple Notification Service (SNS) topics that have server-side encryption disabled. As a best practice, enable server-side encryption for at-rest encryption of message content published to SNS topics. When you publish a message, the SNS encrypts your message as soon as it receives it, and decrypts it just prior to delivery.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::sns::topic']


[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/sns.rego
