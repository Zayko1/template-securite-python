from unittest.mock import patch

from src.tp1.utils.lib import hello_world, choose_interface


def test_when_hello_world_then_return_hello_world():
    assert hello_world() == "hello world"


def test_choose_interface_returns_selected_interface():
    with patch("src.tp1.utils.lib.get_if_list", return_value=["eth0", "lo"]):
        with patch("builtins.input", return_value="0"):
            result = choose_interface()
    assert result == "eth0"


def test_choose_interface_second_option():
    with patch("src.tp1.utils.lib.get_if_list", return_value=["eth0", "wlan0"]):
        with patch("builtins.input", return_value="1"):
            result = choose_interface()
    assert result == "wlan0"


def test_choose_interface_retries_on_invalid_then_valid():
    with patch("src.tp1.utils.lib.get_if_list", return_value=["eth0", "wlan0"]):
        with patch("builtins.input", side_effect=["99", "abc", "1"]):
            result = choose_interface()
    assert result == "wlan0"
