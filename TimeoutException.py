class TimeoutException(Exception):
    """
    Raised in RawSockets.py when no packet we are sniffing for is 
        found for over 60 seconds.
    """
    
    def __init__(self, message=""):
        """
        Purpose: Initializes a new TimeoutException object. 
        :param message: str representing an optional message describing the
                        reason a TimeoutException was raised.
        """
        super().__init__(message)
