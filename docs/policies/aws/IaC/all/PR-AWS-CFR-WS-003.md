



# Title: Ensure AWS WorkSpaces do not use directory type Simple AD.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-WS-003

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-WS-003|
|eval|data.rule.workspace_directory_type|
|message|data.rule.workspace_directory_type_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-workspaces-workspace.html#cfn-workspaces-workspace-directoryid' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_WS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if Simple AD is used for workspace users. MS Active Directory is approved by GS to be used.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::workspaces::workspace', 'aws::directoryservice::simplead']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
