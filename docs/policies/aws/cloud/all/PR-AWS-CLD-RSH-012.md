



# Master Test ID: PR-AWS-CLD-RSH-012


Master Snapshot Id: ['TEST_REDSHIFT_1']

type: rego

rule: [file(redshift.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RSH-012|
|eval: |data.rule.redshift_not_default_port|
|message: |data.rule.redshift_not_default_port_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RSH_012.py|


severity: Low

title: Ensure Redshift database clusters are not using default port(5439) for database connection.

description: It is to check that Redshift cluster is not configured using default port to reduce security risks.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'NIST 800']|
|service: |['redshift']|



[file(redshift.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
