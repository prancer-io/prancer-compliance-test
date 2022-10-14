



# Title: Ensure Transfer Server is not use FTP protocol.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-TRF-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-TRF-002|
|eval|data.rule.transfer_server_protocol|
|message|data.rule.transfer_server_protocol_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/transfer_server' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_TRF_002.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if FTP protocol is not used for AWS Transfer Family server.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['Best Practice']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_transfer_server']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/storage.rego
