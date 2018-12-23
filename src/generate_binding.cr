# export LLVM_CONFIG=/usr/local/opt/llvm/bin/llvm-config
# http://fm4dd.com/openssl/eckeycreate.htm
# https://stackoverflow.com/questions/34404427/how-do-i-check-if-an-evp-pkey-contains-a-private-key
# https://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys/
@[Include("/Users/kings/Downloads/openssl-1.1.0j/include/openssl/ec.h")]
@[Include("/Users/kings/Downloads/openssl-1.1.0j/include/openssl/objects.h")]
@[Include("/Users/kings/Downloads/openssl-1.1.0j/include/openssl/evp.h")]
@[Include("/Users/kings/Downloads/openssl-1.1.0j/include/openssl/bn.h")]
@[Link("ssl")]
lib LibSSL
  # fun EC_KEY_generate_key
  # fun EC_KEY_new_by_curve_name
  # fun EC_GROUP_new_by_curve_name
  # fun OBJ_txt2nid
  # fun EVP_PKEY_new
  # fun EVP_PKEY_assign
  # fun EVP_PKEY_get1_EC_KEY
  # fun EVP_PKEY_bits
  # fun EC_KEY_get0_private_key
  # fun EC_KEY_get0_public_key
  # fun BN_bn2hex
  # fun BN_bn2dec
  # fun EC_POINT_new
  # fun EC_POINT_point2hex
  # fun EC_POINT_hex2point
  # fun EC_POINT_bn2point
  # fun EC_KEY_free
  # fun EC_POINT_free
  # fun EC_GROUP_free
  #
  # fun EC_KEY_set_private_key
  # fun EC_KEY_set_public_key
  # fun BN_hex2bn
  # fun BN_new
  # fun BN_clear_free
  #
  # fun ECDSA_do_sign
  # fun ECDSA_SIG_get0
  # fun ECDSA_SIG_get0_r
  # fun EC_KEY_set_asn1_flag
  # fun ECDSA_do_verify
  # fun EC_KEY_get0_group
  #
  # fun ECDSA_SIG_free
  # fun ECDSA_SIG_new
  # fun ECDSA_SIG_set0
  fun EC_POINT_mul
end
