



# Master Test ID: PR-AWS-CLD-RSH-013


Master Snapshot Id: ['TEST_REDSHIFT_1']

type: rego

rule: [file(redshift.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RSH-013|
|eval: |data.rule.redshift_automated_backup|
|message: |data.rule.redshift_automated_backup_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RSH_013.py|


severity: Medium

title: Ensure automated backups are enabled for Redshift cluster.

description: It is to check automated backup is turned on in order to recover data in the event of failures.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'NIST 800']|
|service: |['redshift']|



[file(redshift.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
