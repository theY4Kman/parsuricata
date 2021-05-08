__version__ = "0.2.3"

from ._parser import parser
from .rules import *
from .transformer import RuleTransformer


def parse_rules(source: str) -> RulesList:
    return parser.parse(source)
