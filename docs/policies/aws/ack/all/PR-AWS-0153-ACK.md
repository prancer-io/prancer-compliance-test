



# Title: AWS SNS topic encrypted using default KMS key instead of CMK


***<font color="white">Master Test Id:</font>*** TEST_SNS_1

***<font color="white">Master Snapshot Id:</font>*** ['ACK_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([sns.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-0153-ACK|
|eval|data.rule.sns_encrypt_key|
|message|data.rule.sns_encrypt_key_err|
|remediationDescription||
|remediationFunction||


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies Amazon Simple Notification Service (SNS) topics that are encrypted with the default AWS Key Management Service (KMS) keys. As a best practice, use Customer Master Keys (CMK) to encrypt the data in your SNS topics and ensure full control over your data.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['ack']|



[sns.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/ack/sns.rego
