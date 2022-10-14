



# Title: Ensure that Workspace root volumes is encrypted.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-WS-002

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-WS-002|
|eval|data.rule.workspace_root_volume_encrypt|
|message|data.rule.workspace_root_volume_encrypt_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_WS_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It checks if encryption is enabled for workspace root volumes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_workspaces_workspace']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
