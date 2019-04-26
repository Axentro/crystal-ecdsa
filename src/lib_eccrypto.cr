# This is using a path to the default installed version of openSSL installed on the operating system.
# This library requires openssl to be installed
# This library requires that the encryption.o C library to be pre-built and residing in the sibling 'encryption' directory
#
@[Link(ldflags: "`printf %s '#{__DIR__}/../encryption/*.o'`")]
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libcrypto || printf %s '-lcrypto'`")]
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libssl || printf %s '-lssl -lcrypto'`")]
lib LibECCrypto
  alias EcKeySt = Void
  alias EVP_PKEY = Void*
  alias EC_KEY = Void*
  alias EcPoint = Void*
  alias BIGNUM = Void*

  type EcGroup = Void*

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
  fun BN_bin2bn(s : Void*, len : LibC::Int, ret : BIGNUM) : BIGNUM 
  fun BN_bn2bin(a : Void*, to : LibC::Char*) : LibC::Int

  fun BN_new : LibC::Int*
  fun BN_clear_free(a : Void*)
  fun BN_num_bits(a : Void*) : LibC::Int

  fun BN_CTX_new : Void*
  fun BN_CTX_start(Void*)
  fun BN_CTX_end(Void*)
  fun BN_CTX_free(Void*)
    

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
  fun EC_POINT_point2hex(x0 : EcGroup, x1 : EcPoint, form : PointConversionFormT, ctx : Void*) : LibC::Char*
  fun EC_POINT_hex2point(x0 : EcGroup, x1 : LibC::Char*, x2 : EcPoint, x3 : Void*) : EcPoint
  fun EC_POINT_bn2point(x0 : EcGroup, x1 : LibC::Int*, x2 : EcPoint) : EcPoint
  fun EC_POINT_point2bn(x0 : EcGroup, x1 : EcPoint, form : PointConversionFormT, x1 : LibC::Int*, ctx : Void*) : LibC::Int
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
  fun ECDSA_do_verify(dgst : UInt8*, dgst_len : LibC::Int, sig : EcdsaSig2, eckey : Void*) : LibC::Int

  # Use our own Bignum so we can work with the ECDSA_SIG_Struct directly
  # as we were originally using the setters and getters from OpenSSL 1.1.1
  # but this way we can still use older versions of OpenSSL which is much
  # easier for portability
  struct Bignum
    d : LibC::ULong*
    top : LibC::Int
    dmax : LibC::Int
    neg : LibC::Int
    flags : LibC::Int
  end

  # Use own own struct so we can get the r,s as our own BigNum
  struct ECDSA_SIG_Struct
    r : BigNum*
    s : BigNum*
  end

  # Use this version of the ECDSA_SIG to set the r,s
  struct ECDSA_SIG_Struct_setter
    r : LibC::Int*
    s : LibC::Int*
  end

  # Set some types and aliases we can use to work with ECDSA_SIG and Bignum
  type EcdsaSig = ECDSA_SIG_Struct*
  alias EcdsaSig2 = ECDSA_SIG_Struct_setter*
  type BigNum = Bignum*

  # frees a ECDSA_SIG structure
  # param:  sig  pointer to the ECDSA_SIG structure
  fun ECDSA_SIG_free(sig : EcdsaSig)

  # Allocates and initialize a ECDSA_SIG structure
  # return: pointer to a ECDSA_SIG structure or NULL if an error occurred
  fun ECDSA_SIG_new : EcdsaSig

  fun EC_POINT_mul(group : EcGroup, r : EcPoint, n : LibC::Int*, q : EcPoint, m : LibC::Int*, ctx : LibC::Int*) : LibC::Int

  # function to return the number of bits needed to represent a field element
  fun EC_GROUP_get_degree(group : EcGroup) : LibC::Int

  # function to return the EC_GROUP object of a EC_KEY object
  fun EC_KEY_get0_group(key : EC_KEY) : EcGroup

  # encrypt message function
  fun encrypt_message(message : UInt8*, message_size : LibC::Int, group_id : LibC::Int,
                      hex_receiver_public_key : UInt8*,
                      epubk : UInt8**, epubk_len : LibC::SizeT*,
                      iv : UInt8**, iv_len : LibC::Int*,
                      tag : UInt8**, tag_len : LibC::Int*,
                      ciphertext : UInt8**, ciphertext_len : LibC::SizeT* ) : LibC::Int

  # decrypt message function
  fun decrypt_message(group_id : LibC::Int, hex_receiver_private_key : UInt8*,
                      epubk : UInt8*, epubk_len : LibC::SizeT,
                      iv : UInt8*, iv_len : LibC::Int,
                      tag : UInt8*, tag_len : LibC::Int,
                      ciphertext : UInt8*, ciphertext_len : LibC::SizeT,
                      plain_text : UInt8**) : LibC::Int

end
