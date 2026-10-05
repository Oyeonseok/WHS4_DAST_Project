"""Shared agent invocation errors used across adapter implementations."""


class AgentInvocationError(RuntimeError):
    """A model process failed before returning a usable structured result."""
