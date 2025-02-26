from abc import ABC, abstractmethod
import logging

class IncidentResponder(ABC):
    """Abstract base class for incident responders."""

    def __init__(self, instance_id):
        self.instance_id = instance_id
        self.logger = logging.getLogger(self.__class__.__name__)  # Logger per class

    @abstractmethod
    def respond(self):
        """Responds to an incident.  Must be implemented by subclasses."""
        pass
