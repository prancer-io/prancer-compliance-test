



# Title: Ensure that Workspace user volumes is encrypted


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-WS-001

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-WS-001|
|eval|data.rule.workspace_volume_encrypt|
|message|data.rule.workspace_volume_encrypt_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_WS_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirements. Your data is transparently encrypted while being written and transparently decrypted while being read from your storage volumes, therefore the encryption process does not require any additional action from you  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_workspaces_workspace']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
