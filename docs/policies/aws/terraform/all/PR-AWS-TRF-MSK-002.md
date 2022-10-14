



# Title: Ensure data is Encrypted in transit (TLS)


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-MSK-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-MSK-002|
|eval|data.rule.msk_in_transit_encryption|
|message|data.rule.msk_in_transit_encryption_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_MSK_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Ensure data is Encrypted in transit (TLS)  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_msk_cluster']


[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/msk.rego
