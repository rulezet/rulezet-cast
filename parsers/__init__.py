from parsers.formats.sigma_parser import SigmaParser
from parsers.formats.suricata_parser import SuricataParser
from parsers.formats.yara_parser import YaraParser
from parsers.formats.crs_parser import CrsParser
from parsers.formats.nse_parser import NseParser
from parsers.formats.nova_parser import NovaParser


ALL_PARSERS = [
    YaraParser(),
    SigmaParser(),
    SuricataParser(),
    CrsParser(),
    NseParser(),
    NovaParser(),
    # add new parsers here as you implement them
]