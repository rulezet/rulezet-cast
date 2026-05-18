from parsers.formats.sigma_parser import SigmaParser
from parsers.formats.suricata_parser import SuricataParser
from parsers.formats.yara_parser import YaraParser
from parsers.formats.crs_parser import CrsParser

ALL_PARSERS = [
    YaraParser(),
    SigmaParser(),
    SuricataParser(),
    CrsParser(),
    # add new parsers here as you implement them
]