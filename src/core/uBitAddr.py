# This code interfaces with the custom BitAddr CircuitPython module to
# generate Bitcoin addresses and private keys
#
# Author: Josh McIntyre
#

import busio
import board
import time
import os
import adafruit_thermal_printer
import adafruit_character_lcd.character_lcd_i2c as character_lcd
import bitaddr

# This class implements a basic Bitcoin hardware wallet
class uBitAddr:

    # Class "constants"

    # Supported output types
    OUTPUT_DISPLAY = 0
    OUTPUT_PRINTER = 1
    OUTPUT_SERIAL = 2

    DISPLAY_INTERVAL = 60

    # Supported entropy sources
    # All the supported Adafruit M4 boards have a built in CRNG
    # But it could be possible in the future to support
    # accelerometers, diceware, etc. for entropy
    ENTROPY_CRNG = 0

    # Supported currencies
    # BTC and BCH are the default
    BTCBCH = 0
    LTC = 1

    # Initialize the object with a desired output and entropy source
    def __init__(self, output=OUTPUT_DISPLAY, entropy_source=ENTROPY_CRNG, currency=BTCBCH, bch=False):

        self.output = output
        self.entropy_source = entropy_source
        self.currency = currency
        self.bch = bch

    # Wrapper that calls the right function depending on the output
    def generate_and_output(self):

        address, privkey = self.generate_address_privkey()

        try:
            if self.output == self.OUTPUT_DISPLAY:
                self.display_address_privkey(address, privkey)
            elif self.output == self.OUTPUT_PRINTER:
                self.print_address_privkey(address, privkey)
            else:
                # If another option isn't available, print to serial
                print("Address: " + address)
                print("Private Key (WIF): " + privkey)
        except Exception as e:
            print(e)
            print("Unable to output address and privkey")

    # Get entropy based on the desired source
    def get_entropy_str(self):

        if self.entropy_source == self.ENTROPY_CRNG:
            return str(os.urandom(32))
        else:
            raise Exception("No sufficient entropy source specified")

    # Generate address and private key
    def generate_address_privkey(self):

        if self.currency == self.LTC:
            address, privkey = bitaddr.get_address_ltc(self.get_entropy_str(), self.get_entropy_str())
        else:
            address, privkey = bitaddr.get_address(self.get_entropy_str(), self.get_entropy_str(), self.bch)

        # Strip extra buffer garbage
        # The buffer is currently 70 characters on the C side to be safe,
        # but the data won't fill that and we'll see some garbage on the Python side.
        # Note that address lengths can vary a few characters depending on the address type.
        # However here we use a constant, known address generation scheme for basic P2PKH addresses,
        # and can therefore safely use a constant size.
        # Fixing this on the firmware side would be a good future item to address
        if self.bch:
            address = address.replace("bitcoincash:", "")
            address = address[:42]
        else:
            address = address[:34]

        privkey = privkey[:51]

        return (address, privkey)

    # Print a paper wallet with the thermal receipt printer
    def print_address_privkey(self, address, privkey, print_privkey=True):

        # Intialize the printer
        uart = busio.UART(board.TX, board.RX, baudrate=19200)
        ThermalPrinter = adafruit_thermal_printer.get_printer_class(2.69)
        printer = ThermalPrinter(uart)

        printer.bold = True

        # Warm up and wait so we get the best print quality
        printer.warm_up()
        time.sleep(2)

        # Print the address information
        printer.feed(3)
        printer.print("Address:")
        printer.print(address)

        if print_privkey:
            printer.feed(3)
            printer.print("Private Key (WIF):")
            printer.print(privkey)

        printer.feed(3)

    # Prepare the data for display on the character screen
    def prep_data(self, data, colmax):

        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

        prepped_data = ""
        for i in range(0, len(data)):
            if i != 0 and i % colmax == 0:
                prepped_data = prepped_data + "\n"

            if data[i] in alphabet:
                prepped_data = prepped_data + data[i]

        return prepped_data

    # Display the address or private key on a character LCD
    def display_address_privkey(self, address, privkey):

        # Initialize the board
        i2c = busio.I2C(board.SCL, board.SDA)
        cols = 20
        rows = 4
        lcd = character_lcd.Character_LCD_I2C(i2c, cols, rows)
        lcd.backlight = True

        # Prep the address and display, wait N seconds,
        # then display the private key
        while True:
            lcd.clear()
            address = self.prep_data(address, cols)
            lcd.message = "Address:\n" + address

            time.sleep(self.DISPLAY_INTERVAL)

            lcd.clear()
            privkey = self.prep_data(privkey, cols)
            lcd.message = "Private Key (WIF):\n" + privkey

            time.sleep(self.DISPLAY_INTERVAL)


# This is the main entry point for the program
uba = uBitAddr(output=uBitAddr.OUTPUT_SERIAL, currency=uBitAddr.LTC)
uba.generate_and_output()