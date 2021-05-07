from parsuricata import parse_rules


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


def test_multiline_rules():
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
