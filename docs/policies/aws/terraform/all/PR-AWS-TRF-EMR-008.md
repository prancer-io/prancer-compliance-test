



# Title: Ensure Cluster level logging is enabled for EMR.


***<font color="white">Master Test Id:</font>*** PR-AWS-TRF-EMR-008

***<font color="white">Master Snapshot Id:</font>*** ['TRF_TEMPLATE_SNAPSHOT']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([emr.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-TRF-EMR-008|
|eval|data.rule.emr_cluster_level_logging|
|message|data.rule.emr_cluster_level_logging_err|
|remediationDescription|Make sure you are following the Terraform template format presented <a href='https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/emr_cluster' target='_blank'>here</a>|
|remediationFunction|PR_AWS_TRF_EMR_008.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** It checks if cluster level logging is enabled for EMR cluster created. This determines whether Amazon EMR captures detailed log data to Amazon S3.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|git|
|compliance|['APRA', 'CCPA', 'HITRUST', 'LGPD', 'MAS TRM', 'PCI-DSS', 'NIST 800', 'NIST SP', 'NIST CSF']|
|service|['terraform']|


***<font color="white">Resource Types:</font>*** ['aws_emr_cluster']


[emr.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/terraform/emr.rego
