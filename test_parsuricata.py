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
    assert repr(option.settings) == "'heymum'"


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
    assert repr(option.settings) == "!'heymum'"


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
    assert repr(option.settings) == "'heymum'"


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


EXAMPLE_RULES_CORPUS = '''
alert ip [127.0.0.1, 127.0.0.2] any -> ![8.8.8.8/24, 1.1.1.1] any ( msg:"Test rule"; sid:12345678; rev:1; )
alert ip any 80:100 -> any any ( msg:"Fart"; )
alert ip any 80: -> any any ( msg:"Fart"; )
alert ip any :100 -> any any ( msg:"Fart"; )
alert ip any any -> any any ( msg:"Test rule"; tls.cert_subject; content:"CN=*.googleusercontent.com"; sid:12345678; rev:1; )
'''

EXAMPLE_RULES = EXAMPLE_RULES_CORPUS.strip().splitlines()


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
