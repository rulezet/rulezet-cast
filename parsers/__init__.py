from parsers.formats.sigma_parser import SigmaParser
from parsers.formats.yara_parser import YaraParser

ALL_PARSERS = [
    YaraParser(),
    SigmaParser(),
    # add new parsers here as you implement them
]