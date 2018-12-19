
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libcrypto || printf %s '-lcrypto'`")]
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libssl || printf %s '-lssl -lcrypto'`")]
lib LibSSL
  type EcGroup = Void*
  alias EcPoint = Void*
  fun OBJ_txt2nid(s : LibC::Char*) : LibC::Int
  fun EC_KEY_new_by_curve_name(i : LibC::Int) : Void*
  fun EC_GROUP_new_by_curve_name(nid : LibC::Int) : EcGroup
  fun EC_POINT_new(group : EcGroup) : EcPoint
  fun EC_POINT_hex2point(x0 : EcGroup, x1 : LibC::Char*, x2 : EcPoint, x3: Void*) : EcPoint
  fun EC_KEY_get0_group(key : Void*) : EcGroup
end

hex_private_key = "a5b9a2406e2c797e74c59778820c66dbbcd6acfa60e6f07ae82183151806e0e5"
hex_public_key = "04e6b642e45eb17ea0579af07b08d02502e14bd39daef961bd3edae7f11d28d1504f85f6ec74551b3ecff1277b93cb25abf9e7491b563524e8a92656a4cbaaa25b".upcase
eccgrp_id = LibSSL.OBJ_txt2nid("secp256k1")
p myecc = LibSSL.EC_KEY_new_by_curve_name(eccgrp_id)
p eccgrp = LibSSL.EC_KEY_get0_group(myecc)
p ec_point = LibSSL.EC_POINT_new(eccgrp)
p hex_public_key
p LibSSL.EC_POINT_hex2point(eccgrp, hex_public_key.to_unsafe, ec_point, nil)
