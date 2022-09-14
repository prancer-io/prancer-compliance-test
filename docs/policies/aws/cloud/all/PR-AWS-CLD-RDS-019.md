



# Master Test ID: PR-AWS-CLD-RDS-019


Master Snapshot Id: ['TEST_RDS_01']

type: rego

rule: [file(database.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RDS-019|
|eval: |data.rule.db_instance_monitor|
|message: |data.rule.db_instance_monitor_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-rds-database-instance.html#cfn-rds-dbinstance-monitoringinterval' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RDS_019.py|


severity: Medium

title: Enhanced monitoring for Amazon RDS instances is enabled

description: This New Relic integration allows you to monitor and alert on RDS Enhanced Monitoring. You can use integration data and alerts to monitor the DB processes and identify potential trouble spots as well as to profile the DB allowing you to improve and optimize their response and cost  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['GDPR', 'CSA CCM', 'CIS', 'HITRUST', 'ISO 27001', 'NIST 800', 'NIST CSF', 'SOC 2']|
|service: |['rds']|



[file(database.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
