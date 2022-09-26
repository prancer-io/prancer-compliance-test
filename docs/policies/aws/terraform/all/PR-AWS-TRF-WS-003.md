



# Title: Ensure AWS WorkSpaces do not use directory type Simple AD.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-WS-003

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-WS-003|
|eval|data.rule.workspace_directory_type|
|message|data.rule.workspace_directory_type_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_WS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if Simple AD is used for workspace users. MS Active Directory is approved by GS to be used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_workspaces_workspace', 'aws_directory_service_directory']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/all.rego
