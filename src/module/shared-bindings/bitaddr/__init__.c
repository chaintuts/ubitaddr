#include <assert.h>
#include <string.h>

#include "py/obj.h"
#include "py/runtime.h"
#include "shared-bindings/bitaddr/__init__.h"
#include "supervisor/shared/translate.h"

//| :mod:`bitaddr` --- Cryptocurrency address functions
//| ========================================================
//|
//| .. module:: bitaddr
//|   :synopsis: Cryptocurrency address functions
//|   :platform: SAMD21
//|

const size_t ADDRESS_STR_LENGTH = 70;
const size_t PRIVKEY_STR_LENGTH = 70;

//| .. function:: get_address_privkey
//|
//|   Returns a Bitcoin or Bitcoin Cash Legacy Address, or a Bitcoin Cash CashAddr address
//|   with a WIF encoded private key
//|
STATIC mp_obj_t bitaddr_get_address(mp_obj_t entropy_privkey, mp_obj_t entropy_ecdsa, mp_obj_t bch) {

	// Convert entropy args needed for secure address generation
	const char* entropy_privkey_char = mp_obj_str_get_str(entropy_privkey);
	const char* entropy_ecdsa_char = mp_obj_str_get_str(entropy_ecdsa);
	int bch_flag = mp_obj_get_int(bch);

	// Create an address cstring long enough to fit any Bitcoin address
	unsigned char address[ADDRESS_STR_LENGTH];
	unsigned char privkey[PRIVKEY_STR_LENGTH];
 	shared_modules_bitaddr_get_address_privkey(address, privkey, entropy_privkey_char, entropy_ecdsa_char, bch_flag);

    	// make the return value
    	mp_obj_tuple_t *addr_key= MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
    	addr_key -> items[0] = mp_obj_new_str((char*) address, ADDRESS_STR_LENGTH);
    	addr_key -> items[1] = mp_obj_new_str((char*) privkey, PRIVKEY_STR_LENGTH);

	return addr_key;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(bitaddr_get_address_obj, bitaddr_get_address);

//| .. function:: get_address_privkey_ltc
//|
//|   Returns a Litecoin address and WIF encoded private key
//|
STATIC mp_obj_t bitaddr_get_address_ltc(mp_obj_t entropy_privkey, mp_obj_t entropy_ecdsa) {

	// Convert entropy args needed for secure address generation
	const char* entropy_privkey_char = mp_obj_str_get_str(entropy_privkey);
	const char* entropy_ecdsa_char = mp_obj_str_get_str(entropy_ecdsa);

	// Create an address cstring long enough to fit any Litecoin address
	unsigned char address[ADDRESS_STR_LENGTH];
	unsigned char privkey[PRIVKEY_STR_LENGTH];
 	shared_modules_bitaddr_get_address_privkey_ltc(address, privkey, entropy_privkey_char, entropy_ecdsa_char);

    	// make the return value
    	mp_obj_tuple_t *addr_key= MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
    	addr_key -> items[0] = mp_obj_new_str((char*) address, ADDRESS_STR_LENGTH);
    	addr_key -> items[1] = mp_obj_new_str((char*) privkey, PRIVKEY_STR_LENGTH);

	return addr_key;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitaddr_get_address_ltc_obj, bitaddr_get_address_ltc);


//| .. function:: get_address_privkey_dgb
//|
//|   Returns a Digibyte address and WIF encoded private key
//|
STATIC mp_obj_t bitaddr_get_address_dgb(mp_obj_t entropy_privkey, mp_obj_t entropy_ecdsa) {

	// Convert entropy args needed for secure address generation
	const char* entropy_privkey_char = mp_obj_str_get_str(entropy_privkey);
	const char* entropy_ecdsa_char = mp_obj_str_get_str(entropy_ecdsa);

	// Create an address cstring long enough to fit any Digibyte address
	unsigned char address[ADDRESS_STR_LENGTH];
	unsigned char privkey[PRIVKEY_STR_LENGTH];
 	shared_modules_bitaddr_get_address_privkey_dgb(address, privkey, entropy_privkey_char, entropy_ecdsa_char);

    	// make the return value
    	mp_obj_tuple_t *addr_key= MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
    	addr_key -> items[0] = mp_obj_new_str((char*) address, ADDRESS_STR_LENGTH);
    	addr_key -> items[1] = mp_obj_new_str((char*) privkey, PRIVKEY_STR_LENGTH);

	return addr_key;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitaddr_get_address_dgb_obj, bitaddr_get_address_dgb);

//| .. function:: get_address_privkey_eth
//|
//|   Returns an Ethereum Address and Hex-encoded Private Key
//|
STATIC mp_obj_t bitaddr_get_address_eth(mp_obj_t entropy_privkey, mp_obj_t entropy_ecdsa) {

	// Convert entropy args needed for secure address generation
	const char* entropy_privkey_char = mp_obj_str_get_str(entropy_privkey);
	const char* entropy_ecdsa_char = mp_obj_str_get_str(entropy_ecdsa);

	// Create an address cstring long enough to fit any Litecoin address
	unsigned char address[ADDRESS_STR_LENGTH];
	unsigned char privkey[PRIVKEY_STR_LENGTH];
 	shared_modules_bitaddr_get_address_privkey_eth(address, privkey, entropy_privkey_char, entropy_ecdsa_char);

    	// make the return value
    	mp_obj_tuple_t *addr_key= MP_OBJ_TO_PTR(mp_obj_new_tuple(2, NULL));
    	addr_key -> items[0] = mp_obj_new_str((char*) address, ADDRESS_STR_LENGTH);
    	addr_key -> items[1] = mp_obj_new_str((char*) privkey, PRIVKEY_STR_LENGTH);

	return addr_key;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitaddr_get_address_eth_obj, bitaddr_get_address_eth);

STATIC const mp_rom_map_elem_t mp_module_bitaddr_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR_get_address), MP_ROM_PTR(&bitaddr_get_address_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_address_ltc), MP_ROM_PTR(&bitaddr_get_address_ltc_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_address_dgb), MP_ROM_PTR(&bitaddr_get_address_dgb_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_address_eth), MP_ROM_PTR(&bitaddr_get_address_eth_obj) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_bitaddr_globals, mp_module_bitaddr_globals_table);

const mp_obj_module_t bitaddr_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_bitaddr_globals,
};
