@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libcrypto || printf %s '-lcrypto'`")]
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libssl || printf %s '-lssl -lcrypto'`")]
lib LibSSL
  fun EC_KEY_generate_key(key : Void*) : LibC::Int
  fun EC_KEY_new_by_curve_name(i : LibC::Int) : Void*
  fun OBJ_txt2nid(s : LibC::Char*) : LibC::Int
  fun EVP_PKEY_new : LibC::Int*
  fun EVP_PKEY_assign(pkey : LibC::Int*, type : LibC::Int, key : Void*) : LibC::Int
  alias EcKeySt = Void
  alias EVP_PKEY = Void*
  alias EC_KEY = Void*
  alias EcPoint = Void*

  fun EVP_PKEY_get1_EC_KEY(pkey : Void*) : EcKeySt*
  fun EVP_PKEY_bits(pkey : Void*) : LibC::Int
  fun EC_KEY_get0_private_key(pkey : Void*) : LibC::Int*
  fun EC_KEY_get0_public_key(key : Void*) : EcPoint

  fun BN_bn2hex(a : Void*) : LibC::Char*
  fun BN_bn2dec(a : Void*) : LibC::Char*

  type EcGroup = Void*
  enum PointConversionFormT
    PointConversionCompressed = 2
    PointConversionUncompressed = 4
    PointConversionHybrid = 6
  end
  fun EC_POINT_new(group : EcGroup) : EcPoint
  fun EC_POINT_point2hex(x0 : EcGroup, x1 : EcPoint, form : PointConversionFormT) : LibC::Char*
  fun EC_POINT_hex2point(x0 : EcGroup, x1 : LibC::Char*, x2 : EcPoint, x3: Void*) : EcPoint
  fun EC_POINT_bn2point(x0 : EcGroup, x1 : LibC::Int*, x2 : EcPoint) : EcPoint
  fun EC_GROUP_new_by_curve_name(nid : LibC::Int) : EcGroup

  fun EC_KEY_free(key : Void*)
  fun EC_POINT_free(point : EcPoint)
  fun EC_GROUP_free(group : EcGroup)

  fun EC_KEY_set_private_key(key : Void*, prv : LibC::Int*) : LibC::Int
  fun EC_KEY_set_public_key(key : Void*, pub : EcPoint) : LibC::Int
  fun BN_hex2bn(a : LibC::Int**, str : LibC::Char*) : LibC::Int
  fun BN_new : LibC::Int*
  fun BN_clear_free(a : Void*)

  type EcdsaSig = Void*
  fun ECDSA_do_sign(dgst : UInt8*, dgst_len : LibC::Int, eckey : Void*) : EcdsaSig
  fun ECDSA_SIG_get0(sig : EcdsaSig, pr : LibC::Int**, ps : LibC::Int**)
  fun ECDSA_SIG_get0_r(sig : EcdsaSig) : Void*
  fun ECDSA_SIG_get0_s(sig : EcdsaSig) : Void*

  fun EC_KEY_set_asn1_flag(eckey : Void*, asn1_flag : LibC::Int)
  fun ECDSA_do_verify(dgst : UInt8*, dgst_len : LibC::Int, sig : EcdsaSig, eckey : Void*) : LibC::Int

  fun ECDSA_SIG_free(sig : EcdsaSig)
  fun ECDSA_SIG_new : EcdsaSig
  fun ECDSA_SIG_set0(sig : EcdsaSig, r : LibC::Int*, s : LibC::Int*) : LibC::Int
end
