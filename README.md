# parsuricata

Parse Suricata rules


# Installation

```bash
pip install parsuricata
```


# Usage

```python
from parsuricata import parse_rules

source = '''
  alert http $HOME_NET any -> !$HOME_NET any (msg: "hi mum!"; content: "heymum"; http_uri; sid: 1;)
'''

rules = parse_rules(source)
print(rules)
#
# alert http $HOME_NET any -> !$HOME_NET any ( \
#   msg: hi mum!; \
#   content: heymum; \
#   http_uri; \
#   sid: 1; \
# )

rule = rules[0]

print(rule.action)
# alert

print(rule.protocol)
# http

print(rule.src)
# $HOME_NET

print(rule.src_port)
# any

print(rule.direction)
# ->

print(rule.dst)
# !$HOME_NET

print(rule.dst_port)
# any

for option in rule.options:
    print(f'{option.keyword} = {option.settings}')
#
# msg = hi mum!
# content = heymum
# http_uri = None
# sid = 1
```
