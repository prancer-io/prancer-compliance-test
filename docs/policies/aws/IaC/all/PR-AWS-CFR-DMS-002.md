



# Title: Ensure DMS replication instance is not publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-DMS-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-DMS-002|
|eval|data.rule.dms_public_access|
|message|data.rule.dms_public_access_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-dms-replicationinstance.html#cfn-dms-replicationinstance-publiclyaccessible' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_DMS_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure DMS replication instance is not publicly accessible, this might cause sensitive data leak.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::dms::replicationinstance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/database.rego
