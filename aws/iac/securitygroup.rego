package rule

# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group.html

default securitygroup = null

ports = [
    "135", "137", "138", "1433", "1434", "20", "21", "22", "23", "25", "3306", "3389", "4333",
    "445", "53", "5432", "5500", "5900"
]

errors := {
    "135": "AWS Security Groups allow internet traffic from internet to Windows RPC port (135)",
    "137": "AWS Security Groups allow internet traffic from internet to NetBIOS port (137)",
    "138": "AWS Security Groups allow internet traffic from internet to NetBIOS port (138)",
    "1433": "AWS Security Groups allow internet traffic from internet to SQLServer port (1433)",
    "1434": "AWS Security Groups allow internet traffic from internet to SQLServer port (1434)",
    "20": "AWS Security Groups allow internet traffic from internet to FTP-Data port (20)",
    "21": "AWS Security Groups allow internet traffic from internet to FTP port (21)",
    "22": "AWS Security Groups allow internet traffic to SSH port (22)",
    "23": "AWS Security Groups allow internet traffic from internet to Telnet port (23)",
    "25": "AWS Security Groups allow internet traffic from internet to SMTP port (25)",
    "3306": "AWS Security Groups allow internet traffic from internet to MYSQL port (3306)",
    "3389": "AWS Security Groups allow internet traffic from internet to RDP port (3389)",
    "4333": "AWS Security Groups allow internet traffic from internet to MSQL port (4333)",
    "445": "AWS Security Groups allow internet traffic from internet to CIFS port (445)",
    "53": "AWS Security Groups allow internet traffic from internet to DNS port (53)",
    "5432": "AWS Security Groups allow internet traffic from internet to PostgreSQL port (5432)",
    "5500": "AWS Security Groups allow internet traffic from internet to VNC Listener port (5500)",
    "5900": "AWS Security Groups allow internet traffic from internet to VNC Server port (5900)",
    "all": "AWS Default Security Group does not restrict all traffic",
    "proto_all": "AWS Security Groups with Inbound rule overly permissive to All Traffic"
}

secgroup_false[port] = false {
    lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.Properties.SecurityGroupIngress[_]
    port := ports[_]

    ingress.CidrIp == "0.0.0.0/0"
    to_number(ingress.FromPort) <= to_number(port)
    to_number(ingress.ToPort) >= to_number(port)
}

secgroup_false[port] = false {
    lower(input.Type) == "aws::ec2::securitygroup"
    ingress := input.Properties.SecurityGroupIngress[_]
    port := ports[_]

    ingress.CidrIpv6 == "::/0"
    to_number(ingress.FromPort) <= to_number(port)
    to_number(ingress.ToPort) >= to_number(port)
}

secgroup_false["all"] = false {
    lower(input.Type) == "aws::ec2::securitygroup"
    lower(input.Properties.GroupName) == "default"
    input.Properties.SecurityGroupIngress[_].CidrIpv6 == "::/0"
}

secgroup_false["all"] = false {
    lower(input.Type) == "aws::ec2::securitygroup"
    lower(input.Properties.GroupName) == "default"
    input.Properties.SecurityGroupIngress[_].CidrIp == "0.0.0.0/0"
}

secgroup_false["proto_all"] = false {
    ingress := input.Properties.SecurityGroupIngress[_]
    ingress.IpProtocol == "-1"
    ingress.CidrIp == "0.0.0.0/0"
}

secgroup_false["proto_all"] = false {
    ingress := input.Properties.SecurityGroupIngress[_]
    ingress.IpProtocol == "-1"
    ingress.CidrIpv6="::/0"
}

securitygroup = true {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(secgroup_false) == 0
}

securitygroup = false {
    lower(input.Type) == "aws::ec2::securitygroup"
    count(secgroup_false) > 0
}

securitygroup_err = error {
    error := concat("\n", [c | secgroup_false[i] == false; c := errors[i]])
}
