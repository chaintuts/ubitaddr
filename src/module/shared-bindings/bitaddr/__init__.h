#ifndef MICROPY_INCLUDED_SHARED_BINDINGS_BITADDR___INIT___H
#define MICROPY_INCLUDED_SHARED_BINDINGS_BITADDR___INIT___H

extern void shared_modules_bitaddr_get_address_privkey(unsigned char* address, unsigned char* privkey, const char* entropy_privkey, const char* entropy_ecdsa, int bch);
extern void shared_modules_bitaddr_get_address_privkey_ltc(unsigned char* address, unsigned char* privkey, const char* entropy_privkey, const char* entropy_ecdsa);
extern void shared_modules_bitaddr_get_address_privkey_dgb(unsigned char* address, unsigned char* privkey, const char* entropy_privkey, const char* entropy_ecdsa);
extern void shared_modules_bitaddr_get_address_privkey_eth(unsigned char* address, unsigned char* privkey, const char* entropy_privkey, const char* entropy_ecdsa);

#endif  // MICROPY_INCLUDED_SHARED_BINDINGS_BITADDR__INIT___H
