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
