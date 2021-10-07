from lark import Lark

from .transformer import RuleTransformer

grammar = r'''
    %ignore " "
    COMMENT: "#" /[^\r\n]/*
    %ignore COMMENT

    _NEWLINE: /[\r\n]+/
    _ESCAPED_NEWLINE: /(\\(\r\n|\r|\n))+/

    start: rules
    rules: (_NEWLINE* rule)* _NEWLINE*

    rule: action protocol target port direction target port "(" body ")"

    !action: "pass"
           | "drop"
           | "reject"
           | "alert"

    !protocol: /[^\s]+/

    ?target: any
           | target_spec

    !any: "any"

    ?target_spec: variable
                | ip
                | cidr
                | "[" target_spec ("," target_spec)* "]"    -> target_grouping
                | "!" target_spec                           -> negated

    variable: /\$[a-z_]+/i

    ip: ip_v4
      | ip_v6

    ?ip_v4: /\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b/
    ?ip_v6: /\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b/

    cidr: cidr_v4
        | cidr_v6

    ?cidr_v4: /\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))\b/
    ?cidr_v6: /\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\/((1(1[0-9]|2[0-8]))|([0-9][0-9])|([0-9])))\b/

    ?port: any
         | port_spec

    ?port_spec: variable
              | integer
              | port_range
              | "[" port_spec ("," port_spec)* "]"    -> port_grouping
              | "!" port_spec                         -> negated

    ?port_grouping_spec: port_spec
                       | port_range

    !port_range: integer ":" integer
               | ":" integer
               | integer ":"

    integer: /\d+/

    !direction: "->"
              | "<>"

    body: _ESCAPED_NEWLINE* (option _ESCAPED_NEWLINE*)+

    option: KEYWORD _SEMICOLON
          | KEYWORD _COLON settings _SEMICOLON

    // Higher priorities, as these terminals are used to demarcate the option name
    // and settings, in a context-free manner.
    _COLON . 2: ":"
    _SEMICOLON . 3: ";"

    KEYWORD: /[a-z0-9_.\-]+/i

    settings: "!" settings_expr   -> negated_settings
            | settings_expr

    ?settings_expr: STRING  -> string
                  | LITERAL -> literal

    STRING: /"[^\r\n]+?"(?=\s*[;])/
    LITERAL: /(?!\s+)([^;\\"]|(?!\\)\\[;\\"])+(?=;)/
'''

parser = Lark(
    start='rules',
    parser='lalr',
    grammar=grammar,
    transformer=RuleTransformer(),
)
