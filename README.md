# Network-Firewall-Solution

This automatuion ristricts domain access per workload .

Specify the attached policy you would like to use in the nwf_policy_name section and keep the name quated .

Under rule_groups , we specify the workload name (must be in uppercase letters) , allowed domains , and source IP address .

EXAMPLE:

nwf_policy_name: "prod-core-network-firewall-policy"

rule_groups:
  - name: "WORKLOAD_EXAMPLE"
    allowed-domains:
     - ".releases.hashicorp.com"
     - ".s3.dualstack.eu-central-1.amazonaws.com"
     - ".pypi.org"
     - ".login.microsoftonline.com"
    source: "10.129.0.0/16"
