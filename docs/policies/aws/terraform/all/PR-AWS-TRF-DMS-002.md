



# Title: Ensure DMS replication instance is not publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-DMS-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-DMS-002|
|eval|data.rule.dms_public_access|
|message|data.rule.dms_public_access_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/dms_replication_instance' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_DMS_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure DMS replication instance is not publicly accessible, this might cause sensitive data leak.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_dms_replication_instance']


[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/database.rego
