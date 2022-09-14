



# Master Test ID: PR-AWS-CLD-RSH-008


Master Snapshot Id: ['TEST_REDSHIFT_1']

type: rego

rule: [file(redshift.rego)]  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id: |PR-AWS-CLD-RSH-008|
|eval: |data.rule.redshift_enhanced_vpc_routing|
|message: |data.rule.redshift_enhanced_vpc_routing_err|
|remediationDescription: |Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/redshift.html#Redshift.Client.describe_clusters' target='_blank'>here</a>|
|remediationFunction: |PR_AWS_CLD_RSH_008.py|


severity: Low

title: Ensure AWS Redshift - Enhanced VPC routing must be enabled.

description: It is to check enhanced VPC routing is enabled or not forces all COPY and UNLOAD traffic between your cluster and your data repositories through your virtual private cloud (VPC) based on the Amazon VPC service.  
  
  

|Title|Description|
| :---: | :---: |
|cloud: |AWS|
|compliance: |['PCI DSS', 'HIPAA', 'NIST 800']|
|service: |['redshift']|



[file(redshift.rego)]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/redshift.rego
