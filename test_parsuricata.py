import pytest

from parsuricata import Option, parse_rules, Rule, Setting


def test_content():
    rules = parse_rules('''
        alert ip any any -> any any (content: "heymum";)
    ''')

    assert len(rules) == 1

    rule = rules[0]
    assert len(rule.options) == 1

    option = rule.options[0]
    assert option.settings == 'heymum'
    assert not option.settings.is_negated
    assert repr(option.settings) == '"heymum"'


def test_literal_content():
    rules = parse_rules('''
        alert ip any any -> any any (content: heymum;)
    ''')

    assert len(rules) == 1

    rule = rules[0]
    assert len(rule.options) == 1

    option = rule.options[0]
    assert option.settings == 'heymum'
    assert not option.settings.is_negated
    assert repr(option.settings) == 'heymum'


def test_negated_content():
    rules = parse_rules('''
        alert ip any any -> any any (content: !"heymum";)
    ''')

    assert len(rules) == 1

    rule = rules[0]
    assert len(rule.options) == 1

    option = rule.options[0]
    assert option.settings == 'heymum'
    assert option.settings.is_negated
    assert repr(option.settings) == '!"heymum"'


def test_multiline_rule():
    rules = parse_rules('''
        alert ip any any -> any any ( \\
            content: "heymum"; \\
        )
    ''')

    assert len(rules) == 1

    rule = rules[0]
    assert len(rule.options) == 1

    option = rule.options[0]
    assert option.settings == 'heymum'
    assert not option.settings.is_negated
    assert repr(option.settings) == '"heymum"'


def test_multiple_rules():
    rules = parse_rules('''
        alert ip any any -> any any (content: "a";)
        alert ip any any -> any any ( content: "b"; \\
        )
        alert ip any any -> any any ( \\
            content: "c"; \\
        )
        alert ip any any -> any any (content: !"d";)
        alert ip any any -> any any ( content: !"e"; \\
        )
        alert ip any any -> any any ( \\
            \\
            content: !"f"; \\
        )
    ''')

    expected = [
        ('a', False),
        ('b', False),
        ('c', False),
        ('d', True),
        ('e', True),
        ('f', True),
    ]
    actual = [
        (option.settings, option.settings.is_negated)
        for rule in rules
        for option in rule.options
    ]
    assert expected == actual


def test_comments():
    rules = parse_rules('''
        # This is a comment
        alert ip any any -> any any (content: "heymum";)
    ''')

    assert len(rules) == 1


@pytest.mark.parametrize('setting,expected', {
    r'"Message with semicolon\;"':
        r'Message with semicolon\;',
    r'"Message with backslashes\\\\\\!"':
        r'Message with backslashes\\\\\\!',
    r'"Message with \"quotes\""':
        r'Message with \"quotes\"',
    r'"Message with \"quotes\" and final backslash\\"':
        r'Message with \"quotes\" and final backslash\\',
    r'"Message with\: colon"':
        r'Message with\: colon',
}.items())
def test_escaped(setting, expected):
    rules = parse_rules(f'''
        alert ip any any -> any any ( \\
            msg:{setting}; \\
        )
    ''')

    expected = [
        Rule('alert', 'ip', 'any', 'any', '->', 'any', 'any', [
            Option('msg', Setting(expected))
        ])
    ]
    actual = rules
    assert expected == actual


def test_spaces_at_ends_of_string():
    rules = parse_rules(f'''
        alert ip any any -> any any ( \\
            msg: " This is a test of spaces. "; \\
        )
    ''')

    expected = [
        Rule('alert', 'ip', 'any', 'any', '->', 'any', 'any', [
            Option('msg', Setting(' This is a test of spaces. '))
        ])
    ]
    actual = rules
    assert expected == actual


EXAMPLE_RULES_CORPUS = r'''
alert ip [127.0.0.1, 127.0.0.2] any -> ![8.8.8.8/24, 1.1.1.1] any ( msg:"Test rule"; sid:12345678; rev:1; )
alert ip any 80:100 -> any any ( msg:"Fart"; )
alert ip any 80: -> any any ( msg:"Fart"; )
alert ip any :100 -> any any ( msg:"Fart"; )
alert ip any any -> any any ( msg:"Test rule"; tls.cert_subject; content:"CN=*.googleusercontent.com"; sid:12345678; rev:1; )

# These rules come from Emerging Threats
alert ip any any -> any any (msg:"SURICATA Applayer Mismatch protocol both directions"; flow:established; app-layer-event:applayer_mismatch_protocol_both_directions; flowint:applayer.anomaly.count,+,1; classtype:protocol-command-decode; sid:2260000; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"GPL NETBIOS SMB-DS Session Setup NTMLSSP asn1 overflow attempt"; flow:established,to_server; content:"|00|"; depth:1; content:"|FF|SMBs"; within:5; distance:3; byte_test:1,!&,128,6,relative; byte_test:4,&,2147483648,48,relative,little; content:!"NTLMSSP"; within:7; distance:54; asn1:double_overflow, bitstring_overflow, relative_offset 54, oversize_length 2048; reference:bugtraq,9633; reference:bugtraq,9635; reference:cve,2003-0818; reference:nessus,12052; reference:nessus,12065; reference:url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx; classtype:protocol-command-decode; sid:2102383; rev:21; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET PHISHING Common Unhidebody Function Observed in Phishing Landing"; flow:established,to_client; file.data; content:"function unhideBody()"; nocase; fast_pattern; content:"var bodyElems = document.getElementsByTagName(|22|body|22|)|3b|"; nocase; content:"bodyElems[0].style.visibility =|20 22|visible|22 3b|"; nocase; distance:0; content:"onload=|22|unhideBody()|22|"; content:"method="; nocase; pcre:"/^["']?post/Ri"; classtype:social-engineering; sid:2029732; rev:2; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, created_at 2020_03_24, deployment Perimeter, signature_severity Minor, tag Phishing, updated_at 2020_03_24;)

# IPv6 rules — https://github.com/theY4Kman/parsuricata/issues/14
alert ip $HOME_NET any -> [2a00:1450:4010:0c0e:0000:0000:0000:005e] any (msg:"msg";)
alert ip $HOME_NET any -> [2a00:1450:4010:0c0e::005e] any (msg:"msg";)
'''

EXAMPLE_RULES = [
    rule
    for rule in EXAMPLE_RULES_CORPUS.strip().splitlines()
    if rule and rule[0] != '#'
]


@pytest.mark.parametrize('source_rule', [
    pytest.param(rule, id=rule)
    for rule in EXAMPLE_RULES
])
def test_parse_to_string_to_parse(source_rule):
    orig_parsed_rules = parse_rules(source_rule)
    orig_parsed_rule = orig_parsed_rules[0]

    stringified_rule = str(orig_parsed_rule)

    twice_parsed_rules = parse_rules(stringified_rule)
    twice_parsed_rule = twice_parsed_rules[0]

    expected = orig_parsed_rule
    actual = twice_parsed_rule
    assert expected == actual
