



# Title: Ensure that Workspace root volumes is encrypted.


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-WS-002

***<font color="white">Master Snapshot Id:</font>*** ['TEST_ALL_04']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([all.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-WS-002|
|eval|data.rule.workspace_root_volume_encrypt|
|message|data.rule.workspace_root_volume_encrypt_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/workspaces.html#WorkSpaces.Client.describe_workspaces' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_WS_002.py|


***<font color="white">Severity:</font>*** High

***<font color="white">Description:</font>*** It checks if encryption is enabled for workspace root volumes.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['PCI-DSS', 'HIPAA', 'GDPR', 'NIST 800']|
|service|['workspace']|



[all.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/all.rego
