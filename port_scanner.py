import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


# Maximum number of ports that can be scanned at once.
MAX_WORKERS = 50

# Connection timeout for each port.
TIMEOUT = 0.3


def scan_port(target, port):
    """
    Scan one TCP port.

    Returns the port number if it is open.
    Returns None if the port is closed, filtered, or unreachable.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            return port

        return None

    except (socket.timeout, socket.error, OSError):
        return None

    finally:
        sock.close()


def port_scanner(target, start_port=1, end_port=1024):
    """
    Scan TCP ports on the specified target.

    Default range:
        1 - 1024

    Returns:
        A sorted list containing open ports.
    """

    target = target.strip()

    if not target:
        return []

    # Validate port range.
    if start_port < 1:
        start_port = 1

    if end_port > 65535:
        end_port = 65535

    if start_port > end_port:
        return []

    # Resolve hostname before starting the scan.
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return []

    open_ports = []

    # Scan multiple ports concurrently.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

        futures = {
            executor.submit(
                scan_port,
                target_ip,
                port
            ): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):

            try:
                result = future.result()

                if result is not None:
                    open_ports.append(result)

            except Exception:
                pass

    # Always return ports in numerical order.
    open_ports.sort()

    return open_ports