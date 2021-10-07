from dataclasses import dataclass
from typing import Any, List, Union

__all__ = [
    'RulesList',
    'Rule',
    'Option',
    'Variable',
    'String',
    'Literal',
    'Setting',
    'NegatedSetting',
    'Negated',
    'PortRange',
    'Grouping',
]


class RulesList(List['Rule']):
    def __str__(self):
        return '\n\n'.join(str(rule) for rule in self)


@dataclass
class Rule:
    action: str
    protocol: str
    src: Any
    src_port: Any
    direction: str
    dst: Any
    dst_port: Any
    options: List['Option']

    def __str__(self):
        return '''
            {action} {protocol} {src} {src_port} {direction} {dst} {dst_port} ( \\\n  {body} \\\n)
        '''.format(
            action=self.action,
            protocol=self.protocol,
            src=self.src,
            src_port=self.src_port,
            direction=self.direction,
            dst=self.dst,
            dst_port=self.dst_port,
            body=' \\\n  '.join(str(option) for option in self.options),
        ).strip()


@dataclass
class Option:
    keyword: str
    settings: 'Setting' = None

    def __str__(self):
        if self.settings is None:
            return f'{self.keyword};'
        else:
            return f'{self.keyword}: {self.settings!r};'


@dataclass(frozen=True)
class Variable:
    identifier: str

    def __str__(self):
        return f'${self.identifier}'


class String(str):
    """A quoted string"""

    def __repr__(self):
        return f'"{self}"'


class Literal(str):
    """An unquoted string"""

    def __repr__(self):
        return str(self)


class Setting(str):
    def __new__(cls, value):
        repr_cls = type(cls.__name__, (cls,), {'__repr__': lambda self: f'{value!r}'})
        return str.__new__(repr_cls, value)

    @property
    def is_negated(self):
        return False


class NegatedSetting(Setting):
    def __new__(cls, value):
        repr_cls = type(cls.__name__, (cls,), {'__repr__': lambda self: f'!{value!r}'})
        return str.__new__(repr_cls, value)

    @property
    def is_negated(self):
        return True


@dataclass(frozen=True)
class Negated:
    value: Any

    def __str__(self):
        return f'!{self.value}'

    def __eq__(self, other):
        return self.value != other

    def __contains__(self, item):
        return item not in self.value


@dataclass
class PortRange:
    start: Union[Variable, int] = None
    end: Union[Variable, int] = None

    def __str__(self):
        return ''.join(
            str(component)
            for component in (self.start, ':', self.end)
            if component is not None
        )

    def __contains__(self, item):
        if self.start is not None and item < self.start:
            return False

        if self.end is not None and item > self.end:
            return False

        return True


class Grouping(list):
    def __str__(self):
        return f'[{", ".join(str(item) for item in self)}]'
