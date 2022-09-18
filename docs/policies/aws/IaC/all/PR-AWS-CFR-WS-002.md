



# Title: Ensure that Workspace root volumes is encrypted.


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-WS-002

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-WS-002|
|eval|data.rule.workspace_root_volume_encrypt|
|message|data.rule.workspace_root_volume_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-workspaces-workspace.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_WS_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It checks if encryption is enabled for workspace root volumes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::workspaces::workspace']


[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/all.rego
