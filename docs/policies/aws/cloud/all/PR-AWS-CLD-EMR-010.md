



# Master Test ID: PR-AWS-CLD-EMR-010


Master Snapshot Id: ['TEST_EMR']

type: rego

rule: [file(emr.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-EMR-010|
|eval: |data.rule.emr_termination_protection_is_enabled|
|message: |data.rule.emr_termination_protection_is_enabled_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/emr.html#EMR.Client.describe_cluster' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_EMR_010.py|


severity: Low

title: Ensure Termination protection is enabled for instances in the cluster for EMR.

description: It checks if the EC2 instances created in EMR cluster are protected against accidental termination.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP', 'NIST CSF']|
|service: |['emr']|



[file(emr.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/emr.rego
