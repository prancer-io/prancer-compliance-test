



# Title: Ensure Database Migration Service (DMS) has not expired certificates


***<font color="white">Master Test Id:</font>*** PR-AWS-CLD-DMS-003

***<font color="white">Master Snapshot Id:</font>*** ['TEST_DMS_03']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([database.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-DMS-003|
|eval|data.rule.dms_certificate_expiry|
|message|data.rule.dms_certificate_expiry_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://docs.aws.amazon.com/cli/latest/reference/dms/describe-certificates.html' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_DMS_003.py|


***<font color="white">Severity:</font>*** Medium

***<font color="white">Description:</font>*** This policy identifies expired certificates that are in AWS Database Migration Service (DMS). AWS Database Migration Service (DMS) Certificate service is the preferred tool to provision, manage, and deploy your DMS endpoint certificates. As a best practice, it is recommended to delete expired certificates.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.g', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-12.1.2', 'MAS TRM', 'MAS TRM 2021-10.2.1', 'MAS TRM 2021-10.2.8', 'MAS TRM 2021-10.2.9', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS v3.2.1-3.6.4', 'PCI-DSS']|
|service|['dms']|



[database.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/database.rego
