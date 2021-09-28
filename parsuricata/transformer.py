from ipaddress import ip_address, ip_interface
from typing import Any, Union

from lark import InlineTransformer, Token, Tree

from .rules import (
    Grouping,
    Negated,
    NegatedSetting,
    Option,
    PortRange,
    Rule,
    RulesList,
    Setting,
    Variable,
)


class RuleTransformer(InlineTransformer):
    str = str

    def rules(self, *rules):
        return RulesList(rules)

    def rule(self,
             action,
             protocol,
             src,
             src_port,
             direction,
             dst,
             dst_port,
             body
             ) -> Rule:
        return Rule(
            action,
            protocol,
            src,
            src_port,
            direction,
            dst,
            dst_port,
            body.children,
        )

    action = str
    protocol = str
    any = str
    direction = str

    def target_grouping(self, *components):
        return Grouping(components)

    def port_grouping(self, *components):
        return Grouping(components)

    def port_range(self, *components):
        if len(components) == 3:
            start, colon, end = components
        elif isinstance(components[0], int):
            (start, colon), end = components, None
        else:
            start, (colon, end) = None, components
        return PortRange(start, end)

    def option(self, keyword: Token, settings: Union[Token, Tree] = None) -> Option:
        if settings is not None:
            value = settings
        else:
            value = None

        return Option(str(keyword), value)

    def settings(self, value: Any):
        return Setting(value)

    def negated_settings(self, value: Any):
        return NegatedSetting(value)

    def variable(self, variable: Token):
        identifier = str(variable)[1:]
        return Variable(identifier)

    def ip(self, tok: Token):
        return ip_address(str(tok))

    def cidr(self, tok: Token):
        return ip_interface(str(tok))

    def string(self, tok: Token):
        return tok.value[1:-1]

    def integer(self, tok):
        return int(tok.value)

    def negated(self, value: Any):
        return Negated(value)
