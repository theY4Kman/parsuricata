__version__ = "0.3.2"

from ._parser import parser
from .rules import *
from .transformer import RuleTransformer


def parse_rules(source: str) -> RulesList:
    return parser.parse(source)
