from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock

# 7 devices x 2 registers = 14 registers
# Even = machine state
# Odd  = operator assigned

INITIAL_REGISTERS = [0] * 14

store = ModbusSlaveContext(
    hr=ModbusSequentialDataBlock(0, INITIAL_REGISTERS)
)

context = ModbusServerContext(slaves=store, single=True)

StartTcpServer(context, address=("0.0.0.0", 5020))