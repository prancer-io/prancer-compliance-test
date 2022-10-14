



# Title: Ensure Termination protection is enabled for instances in the cluster for EMR.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EMR-010

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([emr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EMR-010|
|eval|data.rule.emr_termination_protection_is_enabled|
|message|data.rule.emr_termination_protection_is_enabled_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EMR_010.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** It checks if the EC2 instances created in EMR cluster are protected against accidental termination.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP', 'NIST CSF']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_emr_cluster']


[emr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/emr.rego
