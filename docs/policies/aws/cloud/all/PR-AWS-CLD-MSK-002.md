



# Master Test ID: PR-AWS-CLD-MSK-002


***<font color="white">Master Snapshot Id:</font>*** ['TEST_MSK']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-MSK-002|
|eval|data.rule.msk_in_transit_encryption|
|message|data.rule.msk_in_transit_encryption_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-cluster.html#cfn-msk-cluster-encryptioninfo' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_MSK_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Title:</font>*** Ensure data is Encrypted in transit (TLS)

***<font color="white">Description:</font>*** Ensure data is Encrypted in transit (TLS)  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['GDPR', 'NIST 800']|
|service|['msk']|



[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/msk.rego
