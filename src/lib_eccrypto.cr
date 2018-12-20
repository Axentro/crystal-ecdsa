# This is using a path to the default installed version of openSSL installed on the operating system.
# This library requires openssl 1.1.1 to be installed as we use the ECDSA_SIG getters
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libcrypto || printf %s '-lcrypto'`")]
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libssl || printf %s '-lssl -lcrypto'`")]
lib LibECCrypto
  alias EcKeySt = Void
  alias EVP_PKEY = Void*
  alias EC_KEY = Void*
  alias EcPoint = Void*

  type EcGroup = Void*
  type EcdsaSig = Void*

  enum PointConversionFormT
    PointConversionCompressed   = 2
    PointConversionUncompressed = 4
    PointConversionHybrid       = 6
  end

  # Creates a new ec private (and optional a new public) key.
  # param:  key  EC_KEY object
  # return: 1 on success and 0 if an error occurred.
  fun EC_KEY_generate_key(key : Void*) : LibC::Int

  # Creates a new EC_KEY object using a named curve as underlying
  # EC_GROUP object.
  # param:  nid  NID of the named curve.
  # return: EC_KEY object or NULL if an error occurred.
  fun EC_KEY_new_by_curve_name(i : LibC::Int) : Void*

  # Frees a EC_KEY object.
  # param:  key  EC_KEY object to be freed.
  fun EC_KEY_free(key : Void*)

  # Sets the private key of a EC_KEY object.
  # param:  key  EC_KEY object
  # param:  prv  BIGNUM with the private key (note: the EC_KEY object
  #               will use an own copy of the BIGNUM).
  # return: 1 on success and 0 if an error occurred.
  fun EC_KEY_set_private_key(key : Void*, prv : LibC::Int*) : LibC::Int

  # Sets the public key of a EC_KEY object.
  # param:  key  EC_KEY object
  # param:  pub  EC_POINT object with the public key (note: the EC_KEY object
  #              will use an own copy of the EC_POINT object).
  # return: 1 on success and 0 if an error occurred.
  fun EC_KEY_set_public_key(key : Void*, pub : EcPoint) : LibC::Int

  # Sets the signing algorithm
  fun EC_KEY_set_asn1_flag(eckey : Void*, asn1_flag : LibC::Int)

  # Returns the private key of a EC_KEY object.
  # param:  key  EC_KEY object
  # return: a BIGNUM with the private key (possibly NULL).
  fun EC_KEY_get0_private_key(pkey : Void*) : LibC::Int*

  # Returns the public key of a EC_KEY object.
  # param:  key  the EC_KEY object
  # return: a EC_POINT object with the public key (possibly NULL)
  fun EC_KEY_get0_public_key(key : Void*) : EcPoint

  # From objects.h - gets NID from text
  fun OBJ_txt2nid(s : LibC::Char*) : LibC::Int

  # EVP functions are not documented in evp.h
  fun EVP_PKEY_new : LibC::Int*
  fun EVP_PKEY_assign(pkey : LibC::Int*, type : LibC::Int, key : Void*) : LibC::Int
  fun EVP_PKEY_get1_EC_KEY(pkey : Void*) : EcKeySt*
  fun EVP_PKEY_bits(pkey : Void*) : LibC::Int

  # BN functions are not documented in bn.h
  fun BN_bn2hex(a : Void*) : LibC::Char*
  fun BN_bn2dec(a : Void*) : LibC::Char*
  fun BN_hex2bn(a : LibC::Int**, str : LibC::Char*) : LibC::Int
  fun BN_new : LibC::Int*
  fun BN_clear_free(a : Void*)

  # Creates a new EC_POINT object for the specified EC_GROUP
  # param:  group  EC_GROUP the underlying EC_GROUP object
  # return: newly created EC_POINT object or NULL if an error occurred
  fun EC_POINT_new(group : EcGroup) : EcPoint

  # Encodes an EC_POINT object to an allocated octet string
  # param:  group  underlying EC_GROUP object
  # param:  point  EC_POINT object
  # param:  form   point conversion form
  # param:  pbuf   returns pointer to allocated buffer
  # param:  ctx    BN_CTX object (optional)
  # return: the length of the encoded octet string or 0 if an error occurred
  fun EC_POINT_point2hex(x0 : EcGroup, x1 : EcPoint, form : PointConversionFormT) : LibC::Char*
  fun EC_POINT_hex2point(x0 : EcGroup, x1 : LibC::Char*, x2 : EcPoint, x3 : Void*) : EcPoint
  fun EC_POINT_bn2point(x0 : EcGroup, x1 : LibC::Int*, x2 : EcPoint) : EcPoint
  fun EC_POINT_free(point : EcPoint)

  # Creates a EC_GROUP object with a curve specified by a NID
  # param:  nid  NID of the OID of the curve name
  # return: newly created EC_GROUP object with specified curve or NULL
  #          if an error occurred
  fun EC_GROUP_new_by_curve_name(nid : LibC::Int) : EcGroup

  # Frees a EC_GROUP object
  # param:  group  EC_GROUP object to be freed.
  fun EC_GROUP_free(group : EcGroup)

  # Computes the ECDSA signature of the given hash value using
  # the supplied private key and returns the created signature.
  # param:  dgst      pointer to the hash value
  # param:  dgst_len  length of the hash value
  # param:  eckey     EC_KEY object containing a private EC key
  # return: pointer to a ECDSA_SIG structure or NULL if an error occurred
  fun ECDSA_do_sign(dgst : UInt8*, dgst_len : LibC::Int, eckey : Void*) : EcdsaSig

  # Verifies that the supplied signature is a valid ECDSA
  # signature of the supplied hash value using the supplied public key.
  # param:  dgst      pointer to the hash value
  # param:  dgst_len  length of the hash value
  # param:  sig       ECDSA_SIG structure
  # param:  eckey     EC_KEY object containing a public EC key
  # return: 1 if the signature is valid, 0 if the signature is invalid
  #          and -1 on error
  fun ECDSA_do_verify(dgst : UInt8*, dgst_len : LibC::Int, sig : EcdsaSig, eckey : Void*) : LibC::Int

  # Accessor for r and s fields of ECDSA_SIG
  # param:  sig  pointer to ECDSA_SIG structure
  # param:  pr   pointer to BIGNUM pointer for r (may be NULL)
  # param:  ps   pointer to BIGNUM pointer for s (may be NULL)
  fun ECDSA_SIG_get0(sig : EcdsaSig, pr : LibC::Int**, ps : LibC::Int**)

  # Accessor for r field of ECDSA_SIG
  # param:  sig  pointer to ECDSA_SIG structure
  fun ECDSA_SIG_get0_r(sig : EcdsaSig) : Void*

  # Accessor for s field of ECDSA_SIG
  # param:  sig  pointer to ECDSA_SIG structure
  fun ECDSA_SIG_get0_s(sig : EcdsaSig) : Void*

  # frees a ECDSA_SIG structure
  # param:  sig  pointer to the ECDSA_SIG structure
  fun ECDSA_SIG_free(sig : EcdsaSig)

  # Allocates and initialize a ECDSA_SIG structure
  # return: pointer to a ECDSA_SIG structure or NULL if an error occurred
  fun ECDSA_SIG_new : EcdsaSig

  # Setter for r and s fields of ECDSA_SIG
  # param:  sig  pointer to ECDSA_SIG structure
  # param:  r    pointer to BIGNUM for r (may be NULL)
  # param:  s    pointer to BIGNUM for s (may be NULL)
  fun ECDSA_SIG_set0(sig : EcdsaSig, r : LibC::Int*, s : LibC::Int*) : LibC::Int
end
