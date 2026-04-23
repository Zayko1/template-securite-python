from scapy.all import get_if_list


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    interfaces = get_if_list()
    print("\nInterfaces réseau disponibles :")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")

    while True:
        try:
            choice = int(input("\nChoisissez une interface (numéro) : "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
        except (ValueError, EOFError):
            pass
        print("Choix invalide, réessayez.")
