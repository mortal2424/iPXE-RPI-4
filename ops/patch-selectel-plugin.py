"""Handle structured Selectel API errors in the pinned third-party plugin."""
from pathlib import Path
from certbot_dns_selectel_api_v2 import dns_selectel_api_v2
path = Path(dns_selectel_api_v2.__file__)
source = path.read_text()
source = source.replace('message_parts.append(answer["error"])', 'message_parts.append(str(answer["error"]))')
source = source.replace('message_parts.append(resp.content)', 'message_parts.append(resp.text)')
path.write_text(source)
