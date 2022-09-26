



# Title: Azure Deployment Scope Resource Group should have a remove protection resource lock configured


***<font color="white">Master Test Id:</font>*** PR-AZR-CLD-AML-008

***<font color="white">Master Snapshot Id:</font>*** ['AZRSNP_503', 'AZRSNP_261']

***<font color="white">type:</font>*** rego

***<font color="white">rule:</font>*** file([locks.rego])  
  
  
  
  

|Title|Description|
| :---: | :---: |
|id|PR-AZR-CLD-AML-008|
|eval|data.rule.rg_locks|
|message|data.rule.rg_locks_err|
|remediationDescription|1. In the Settings blade for the resource, resource group, or subscription that you wish to lock, select Locks.<br>2. To add a lock, select Add. If you want to create a lock at a parent level, select the parent. The currently selected resource inherits the lock from the parent. For example, you could lock the resource group to apply a lock to all its resources.<br>3. Give the lock a name and lock level. Optionally, you can add notes that describe the lock.|
|remediationFunction|PR_AZR_CLD_AML_008.py|


***<font color="white">Severity:</font>*** Low

***<font color="white">Description:</font>*** Azure Resource Manager locks provide a way to lock down Azure resources from being deleted or modified. The lock level can be set to either 'CanNotDelete' or 'ReadOnly'. When you apply a lock at a parent scope, all resources within the scope inherit the same lock, and the most restrictive lock takes precedence.<br><br>This policy identifies Azure Resource Groups that do not have a lock set. As a best practice, place a lock on important resources to prevent accidental or malicious modification or deletion by unauthorized users.  
  
  

|Title|Description|
| :---: | :---: |
|cloud|azure|
|compliance|['APRA', 'APRA (CPS 234) Information Security-CPS234-15', 'APRA (CPS 234) Information Security-CPS234-16', 'APRA (CPS 234) Information Security-CPS234-17', 'APRA (CPS 234) Information Security-CPS234-21', 'APRA (CPS 234) Information Security-CPS234-23', 'APRA (CPS 234) Information Security-CPS234-27', 'APRA (CPS 234) Information Security-CPS234-34', 'Azure Security Benchmark', 'Azure Security Benchmark (v3)-AM-4', 'Azure Security Benchmark (v3)-IM-7', 'Azure Security Benchmark (v3)-PA-7', 'Brazilian Data Protection Law (LGPD)-Article 49', 'CIS', 'CIS v1.1 (Azure)-8.3', 'CIS v1.2.0 (Azure)-8.3', 'CIS v1.3.0 (Azure)-8.3', 'CIS v1.3.1 (Azure)-8.3', 'CIS v1.4.0 (Azure)-8.5', 'CSA CCM', 'CSA CCM v.4.0.1-AIS-01', 'CSA CCM v.4.0.1-AIS-02', 'CSA CCM v.4.0.1-AIS-04', 'CSA CCM v.4.0.1-CCC-01', 'CSA CCM v.4.0.1-GRC-03', 'CSA CCM v.4.0.1-IVS-04', 'CSA CCM v.4.0.1-UEM-06', 'CMMC', 'Cybersecurity Maturity Model Certification (CMMC) v.1.02-AM.4.226', 'HITRUST', 'HITRUST v.9.4.2-Control Reference:10.a', 'ISO/IEC 27002:2013', 'ISO/IEC 27002:2013-12.1.2', 'ISO/IEC 27002:2013-14.1.1', 'ISO/IEC 27002:2013-14.1.2', 'ISO/IEC 27002:2013-14.2.1', 'ISO/IEC 27002:2013-14.2.2', 'ISO/IEC 27017:2015', 'ISO/IEC 27017:2015-12.1.2', 'ISO/IEC 27017:2015-14.1.1', 'ISO/IEC 27017:2015-14.1.2', 'ISO/IEC 27017:2015-14.2.1', 'ISO/IEC 27017:2015-14.2.5', 'ISO/IEC 27017:2015-5.1.1', 'ISO/IEC 27018:2019', 'ISO/IEC 27018:2019-12.1.2', 'NIST CSF', 'NIST CSF-PR.IP-1', 'NIST SP', 'NIST SP 800-171 Revision 2-3.4.2', 'NIST SP 800-172-3.4.1e', 'NIST SP 800-172-3.4.2e', 'PCI DSS', 'PCI DSS v3.2.1-6.3']|
|service|['Security']|



[locks.rego]: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/cloud/locks.rego
