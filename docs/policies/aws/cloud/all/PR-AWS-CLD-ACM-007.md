



# Master Test ID: PR-AWS-CLD-ACM-007


***<font color="white">Master Snapshot Id:</font>*** ['TEST_ACM']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([acm.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AWS-CLD-ACM-007|
|eval|data.rule.acm_do_not_have_invalid_or_failed|
|message|data.rule.acm_do_not_have_invalid_or_failed_err|
|remediationDescription|Make sure you are following the Cloudformation template format presented <a href='https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.describe_certificate' target='_blank'>here</a>|
|remediationFunction|PR_AWS_CLD_ACM_007.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Title:</font>*** Ensure AWS Certificate Manager (ACM) does not have invalid or failed certificate.

***<font color="white">Description:</font>*** his policy identifies certificates in ACM which are either in Invalid or Failed state. If the ACM certificate is not validated within 72 hours, it becomes Invalid. In such cases (Invalid or Failed certificate), you will have to request for a new certificate. It is strongly recommended to delete the certificates which are in failed or invalid state.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|AWS|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CMMC', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'CSA CCM v3.0.1-EKM-01', 'CSA CCM v3.0.1-IAM-02', 'CSA CCM v3.0.1-IAM-04', 'CSA CCM v3.0.1-IAM-08', 'CSA CCM v3.0.1-IAM-12', 'CSA CCM v3.0.1-IVS-11', 'CSA CCM v3.0.1-MOS-16', "CyberSecurity Law of the People's Republic of China", "CyberSecurity Law of the People's Republic of China-Article 21", "CyberSecurity Law of the People's Republic of China-Article 31", "CyberSecurity Law of the People's Republic of China-Article 40", 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-CM.2.062', 'HITRUST', 'HITRUST CSF v9.3-Control Reference:01.q', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO 27001', 'ISO 27001:2013-A.8.2.3', 'ISO/IEC 27002', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018', 'ISO/IEC 27018:2019-12.1.2', 'LGPD', 'MAS TRM', 'MAS TRM 2021-7.2.1', 'MAS TRM 2021-7.2.2', 'MLPS', 'MLPS 2.0-8.1.4.1', 'NIST 800', 'NIST 800-171 Rev1-3.5.1', 'NIST 800-171 Rev1-3.5.2', 'NIST 800-53 Rev 5-Authenticator Management \| Public Key-based Authentication', 'NIST 800-53 Rev4-IA-5 (2)(a)', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS v3.2.1-6.3', 'PCI-DSS', 'SOC 2', 'SOC 2-CC6.1', 'SOC 2-CC8.1']|
|service|['acm']|



[acm.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/aws/cloud/acm.rego
