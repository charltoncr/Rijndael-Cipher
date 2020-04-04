# Rijndael-Cipher
rijndael.c is a fast Rijndael Cipher implementation for key sizes and block 
sizes 128, 192 & 256. Include rijndael.h in your code and compile rijndael.c 
with it. rijndael.h includes convenience defines for AES support that is 
simply rijndael with a block size of 128 preselected. Call functions 
rijn_set_key, rijn_encrypt, rijn_decrypt, rijn_cbc_encrypt and 
rijn_cbc_decrypt to encrypt and decrypt data with your code.

See rijndael.c header comments for how to use the rijndael functions.

Compile rijndael_test.c to create a test program for the rijndael 
implementation. rijndael_test.c #includes rijndael.c so you should not link 
with it.

Compile rijndael_bench.c with rijndael.c to create a benchmark program for 
the various rijndael functions.

Ron Charlton
