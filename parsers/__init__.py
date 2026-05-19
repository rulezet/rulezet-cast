from parsers.formats.sigma_parser import SigmaParser
from parsers.formats.suricata_parser import SuricataParser
from parsers.formats.yara_parser import YaraParser
from parsers.formats.crs_parser import CrsParser
from parsers.formats.nse_parser import NseParser
from parsers.formats.nova_parser import NovaParser
from parsers.formats.zeek_parser import ZeekParser
from parsers.formats.wazuh_parser import WazuhParser
from parsers.formats.elastic_parser import ElasticParser


ALL_PARSERS = [
    YaraParser(),
    SigmaParser(),
    SuricataParser(),
    CrsParser(),
    NseParser(),
    NovaParser(),
    ZeekParser(),
    WazuhParser(),
    ElasticParser(),
    # add new parsers here as you implement them
]