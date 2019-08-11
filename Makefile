# This file contains a make script for the uBitAddr application
#
# Author: Josh McIntyre
#

# This block defines makefile variables
SRC_FILES=src/core/*.py 
FIRMWARE_FILES=firmware/*.uf2

BUILD_DIR=bin/microprover

# This rule builds the application
build: $(SRC_FILES) $(FIRMWARE_FILES)
	mkdir -p $(BUILD_DIR)
	cp $(SRC_FILES) $(BUILD_DIR)
	cp $(FIRMWARE_FILES) $(BUILD_DIR)
	mv $(BUILD_DIR)/uBitAddr.py $(BUILD_DIR)/code.py

# This rule cleans the build directory
clean: $(BUILD_DIR)
	rm -r $(BUILD_DIR)/*
	rmdir $(BUILD_DIR)
