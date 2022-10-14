



# Title: Ensure Glacier Backup policy is not publicly accessible


***<font color="white">Master Test Id:</font>*** PR-AWS-CFR-BKP-001

***<font color="white">Master Snapshot Id:</font>*** ['CFR_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([storage.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CFR-BKP-001|
|eval|data.rule.backup_public_access_disable|
|message|data.rule.backup_public_access_disable_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-backup-backupvault.html#cfn-backup-backupvault-accesspolicy' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CFR_BKP_001.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** Public Glacier backup potentially expose existing interfaces to unwanted 3rd parties that can tap into an existing data stream, resulting in data leak to an unwanted party.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|[]|
|service|['cloudformation']|


***<font color="white">Resource Types:</font>*** ['aws::backup::backupvault']


[storage.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/iac/storage.rego
