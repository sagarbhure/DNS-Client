from .utils import dump_data
from .utils import is_valid_hostname
from .utils import is_valid_ip_address
from .utils import is_valid_url
from .utils import get_addrfamily
from .utils import check_ip_address
from .utils import canonicalize
from .utils import validate_hostname

from .connection import Connection
from .connection import ConnectionDOT
from .connection import ConnectionDOH

from .request import RequestDOT
from .request import RequestDOH

from .exceptions import TimeoutConnectionError
from .exceptions import ConnectionException
from .exceptions import ConnectionDOTException
from .exceptions import ConnectionDOHException
from .exceptions import FamilyException
from .exceptions import RequestException
from .exceptions import RequestDOTException
from .exceptions import PipeliningException
from .exceptions import DOHException

PORT_DOT = 853
PORT_DOH = 443

TIMEOUT_CONN = 2
TIMEOUT_READ = 1
SLEEP_TIMEOUT = 0.5
MAX_DURATION = 10

# For the check option
DOH_GET = 0
DOH_POST = 1
DOH_HEAD = 2
# Is the test mandatory?
# legal : RFC compliant
# necessary : should work
# nicetohave : not mentionned in the RFC but good if implemented
# nocrash : edge tests (undocumented) just to see if the server crash (this would be bad)
mandatory_levels = {"legal": 30, "necessary": 20, "nicetohave": 10, "nocrash": 5}

