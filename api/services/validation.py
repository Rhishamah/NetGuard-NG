import socket

from fastapi import HTTPException


def list_interfaces() -> set[str]:
    """Names of the network interfaces that exist on this machine."""
    return {name for _, name in socket.if_nameindex()}


def validate_interface(name: str) -> str:
    """Return `name` if it is a real interface, otherwise raise HTTP 422.

    The name is passed to a subprocess, so only exact matches against the
    machine's own interface list are allowed (this also blocks values such as
    "--help" or "-c" that could be read as extra command-line options).
    """
    if name not in list_interfaces():
        raise HTTPException(
            status_code=422,
            detail=f"Unknown network interface: {name!r}",
        )
    return name
