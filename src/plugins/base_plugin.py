from abc import ABC, abstractmethod

class BasePlugin(ABC):
    """
    Abstract Base Class for all Drishti OSINT Plugins.
    """

    @abstractmethod
    def validate_config(self) -> bool:
        """
        Validates if the necessary configuration/API keys are present.
        Returns True if valid, False otherwise.
        """
        pass

    @abstractmethod
    async def run(self, target: str):
        """
        Executes the plugin against the given target.
        Returns the gathered data (dict, list, etc.).
        """
        pass
