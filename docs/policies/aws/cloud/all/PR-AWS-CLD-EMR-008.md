



# Master Test ID: PR-AWS-CLD-EMR-008


Master Snapshot Id: ['TEST_EMR']

type: rego

rule: [file(emr.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EMR-008|
|eval: |data.rule.emr_cluster_level_logging|
|message: |data.rule.emr_cluster_level_logging_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/emr.html#EMR.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EMR_008.py|


severity: Medium

title: Ensure Cluster level logging is enabled for EMR.

description: It checks if cluster level logging is enabled for EMR cluster created. This determines whether Amazon EMR captures detailed log data to Amazon S3.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP', 'NIST CSF']|
|service: |['emr']|



[file(emr.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/emr.rego
