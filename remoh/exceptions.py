def timeout_connection(signum, frame):
    raise TimeoutConnectionError('Connection timeout')

class TimeoutConnectionError(Exception):
    pass

class ConnectionException(Exception):
    pass

class ConnectionDOTException(ConnectionException):
    pass

class ConnectionDOHException(ConnectionException):
    pass

class FamilyException(ConnectionException):
    pass

class RequestException(Exception):
    pass

class RequestDOTException(RequestException):
    pass

class PipeliningException(Exception):
    pass

class DOHException(Exception):
    pass
