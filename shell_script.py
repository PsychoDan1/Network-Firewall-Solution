#!/usr/bin/env python3
import yaml
with open('settings.yaml', 'rb') as f:
        config = yaml.safe_load(f)
core_config = config['rule_groups']

i = 0

for workload in core_config:
  for domain in (workload['allowed-domains']):
    i = i+1
    print(f'pass http ${workload["name"]} any -> $SQUID_EP any (http.host; dotprefix; content:"{domain}";\
 endswith; msg:"Allow access to {domain} from {workload["source"]}"; priority:1; flow:to_server, established; sid:{i}; rev:1;)')

    
