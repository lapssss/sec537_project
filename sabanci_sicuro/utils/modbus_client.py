from pymodbus.client.sync import ModbusTcpClient

MODBUS_HOST = "modbus"   # nome del container
MODBUS_PORT = 5020

def get_client():
    client = ModbusTcpClient(MODBUS_HOST, port=MODBUS_PORT)
    client.connect()
    return client


def read_device_registers(device_id):
    """
    device_id: 1..7
    returns (state, assigned)
    """
    client = get_client()

    base_addr = (device_id - 1) * 2
    result = client.read_holding_registers(base_addr, 2)

    client.close()

    if result.isError():
        return None, None

    return result.registers[0], result.registers[1]


def write_device_state(device_id, state):
    """
    state: 0 or 1
    """
    client = get_client()
    addr = (device_id - 1) * 2
    client.write_register(addr, state)
    client.close()


def write_device_operator(device_id, assigned):
    """
    assigned: 0 or 1
    """
    client = get_client()
    addr = (device_id - 1) * 2 + 1
    client.write_register(addr, assigned)
    client.close()