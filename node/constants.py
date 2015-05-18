# ######## KADEMLIA CONSTANTS ###########

BIT_NODE_ID_LEN = 160
HEX_NODE_ID_LEN = BIT_NODE_ID_LEN // 4

# Small number representing the degree of
# parallelism in network calls
ALPHA = 3

# Maximum number of contacts stored in a bucket
# NOTE: Should be an even number.
K = 24  # pylint: disable=invalid-name

# Maximum number of contacts stored in the
# replacement cache of a bucket
# NOTE: Should be an even number.
CACHE_K = 32

# Timeout for network operations
# [seconds]
RPC_TIMEOUT = 0.1

# Delay between iterations of iterative node lookups
# (for loose parallelism)
# [seconds]
ITERATIVE_LOOKUP_DELAY = RPC_TIMEOUT / 2

# If a KBucket has not been used for this amount of time, refresh it.
# [seconds]
REFRESH_TIMEOUT = 60 * 60 * 1000  # 1 hour

# The interval at which nodes replicate (republish/refresh)
# the data they hold
# [seconds]
REPLICATE_INTERVAL = REFRESH_TIMEOUT

# The time it takes for data to expire in the network;
# the original publisher of the data  will also republish
# the data at this time if it is still valid
# [seconds]
DATE_EXPIRE_TIMEOUT = 86400  # 24 hours

# ####### IMPLEMENTATION-SPECIFIC CONSTANTS ###########

# The interval in which the node should check whether any buckets
# need refreshing or whether any data needs to be republished
# [seconds]
CHECK_REFRESH_INTERVAL = REFRESH_TIMEOUT / 5

# Max size of a single UDP datagram.
# Any larger message will be spread accross several UDP packets.
# [bytes]
UDP_DATAGRAM_MAX_SIZE = 8192  # 8 KB

# You should change this value before starting OB for the first time.
# It is very recommended to change it to a strong password.
DB_PASSPHRASE = "passphrase"

DB_PATH = "db/ob.db"

VERSION = "0.4.0"

SATOSHIS_IN_BITCOIN = 100000000

# The IP of the default DNSChain Server used to validate namecoin addresses
DNSCHAIN_SERVER_IP = "192.184.93.146"

