



# Master Test ID: TEST_DB_Firewallrules


Master Snapshot Id: ['ASO_TEMPLATE_SNAPSHOT']

type: rego

rule: file(dbfirewallrules.rego)

evals: [
    {
       'ID': 'PR-AZR-0082-ASO'
       'eval': 'data.rule.db_firewall'
       'message': 'data.rule.db_firewall_err'
       'remediationDescription': ''
       'remediationFunction': ''
    }
]

severity: Medium

title: SQL Server Firewall rules allow access to any Azure internal resources

description: Firewalls grant access to databases based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.

tags: [
    {
       'cloud': 'git'
       'compliance': '[]'
       'service': '['aso']'
    }
]