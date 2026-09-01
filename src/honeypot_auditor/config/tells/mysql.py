from __future__ import annotations

import re

MYSQL_EOL_RE = re.compile(r"5\.5\.\d+-0ubuntu0\.14\.04", re.IGNORECASE)
MYSQL_STOCK_CAP_BLOCK = b"\xff\xf7\x08\x02\x00\x0f\x80"
MYSQL_PKT_ORDER_CODE = 1156
