



# Title: Ensure client authentication is enabled with TLS (mutual TLS authentication)


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-MSK-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([msk.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-MSK-003|
|eval|data.rule.msk_in_transit_encryption_tls|
|message|data.rule.msk_in_transit_encryption_tls_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_MSK_003.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** Enable TLS by setting EncryptionInfo.EncryptionInTransit.ClientBroker value to 'TLS'. to provide trasport layes security to MSK instance  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_msk_cluster']


[msk.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/msk.rego
