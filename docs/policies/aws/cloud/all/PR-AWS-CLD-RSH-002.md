



# Master Test ID: PR-AWS-CLD-RSH-002


Master Snapshot Id: ['TEST_REDSHIFT_1']

type: rego

rule: [file(redshift.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RSH-002|
|eval: |data.rule.redshift_public|
|message: |data.rule.redshift_public_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-redshift-cluster.html' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RSH_002.py|


severity: High

title: AWS Redshift clusters should not be publicly accessible

description: This policy identifies AWS Redshift clusters which are accessible publicly.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['CSA CCM', 'GDPR', 'HITRUST', 'ISO 27001', 'NIST 800', 'SOC 2']|
|service: |['redshift']|



[file(redshift.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
