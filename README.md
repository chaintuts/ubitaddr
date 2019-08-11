## General
____________

### Author
* Josh McIntyre

### Website
* jmcintyre.net

### Overview
* uBitAddr is an offline Bitcoin address generator for microcontroller platforms

## Development
________________

### Git Workflow
* master for releases (merge development)
* development for bugfixes and new features

### Building (Python and Prebuilt Firmware)
* make build
Build the application
* make clean
Clean the build directory

### Building Custom CircuitPython
* Full CircuitPython source is not included in this repo for brevity/ease of reading source
* To build the custom distribution, clone CircuitPython and checkout branch 4.1.x
* Copy the source in src/module to the matching folders in CircuitPython
* Follow the CircuitPython build instructions for M4 boards (ItsyBitsy M4, Grand Central M4, Metro M4)

### Features
* Generate a random Bitcoin private key (WIF format) and address (Legacy format)
* Display the address and private key on a character LCD screen, rotating every 30 seconds
* Print the address and private key via a thermal receipt printer

### Requirements
* Requires CircuitPython with custom BitAddr module

### Platforms
* Adafruit M4 microcontrollers (ItsyBitsy M4, Grand Central M4, Metro M4)

## Usage
____________

### Firmware installation
* Double tap the reset button on the board when connected to a computer via USB
* Drag the appropriate firmware file (.uf2) for the desired board to the filesystem
* Wait for board to restart automatically

### Peripheral installation
* Wire up the desired output - currently supports a character LCD with I2C backpack, thermal receipt printer, or output to PC via USB cable (no accessories needed)

### Code installation
* Edit "code.py" to init uBitAddr class with desired output
* Copy "code.py" to CIRCUITPY directory

### General usage
* Once the code is loaded, restart the board to automatically generate and output an address

