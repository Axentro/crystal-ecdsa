require "openssl"
require "secp256k1"
require "./lib_eccrypto"

module ECCrypto
  # Creates a Key Pair
  def self.create_key_pair
    # Create the public/private EC key pair
    gen_res = Secp256k1::Keypair.new
    raise "Error could not generate an EC public/private key pair" if gen_res.nil?

    #  Get the private key
    bn = gen_res.get_secret
    raise "Error could not get the private key" if bn.nil?
    private_key = bn.downcase

    # Get the public key
    ec_point = gen_res.public_key
    raise "Error could not get the public key" if ec_point.nil?
    public_key_pointer = Secp256k1::Util.public_key_uncompressed_prefix ec_point
    raise "Error could not get the public key pointer" if public_key_pointer.nil?
    public_key = public_key_pointer.downcase

    return create_key_pair if private_key.hexbytes? == nil || private_key.size != 64
    return create_key_pair if public_key.hexbytes? == nil || public_key.size != 130

    {
      hex_private_key: private_key,
      hex_public_key:  public_key,
    }
  end

  def self.sha256(base : Bytes | String) : String
    hash = OpenSSL::Digest.new("SHA256")
    hash.update(base)
    hash.hexdigest
  end

  # Signs a message with a private key
  def self.sign(hex_private_key : String, message : String)
    # Create a EC key structure, setting the group type from NID
    eccgrp_id = LibECCrypto.OBJ_txt2nid("secp256k1")
    raise "Error could not set EC group" unless eccgrp_id != 0
    myecc = LibECCrypto.EC_KEY_new_by_curve_name(eccgrp_id)
    raise "Error could not create curve" if myecc.null?

    # set signing algo
    LibECCrypto.EC_KEY_set_asn1_flag(myecc, 1)

    # convert hex private key to binary
    bn = LibECCrypto.BN_new
    raise "Error could not create a new bn" if bn.null?
    binary_private_key = LibECCrypto.BN_hex2bn(pointerof(bn), hex_private_key)
    raise "Error private key binary is wrong size" if binary_private_key != 64

    # add binary private key to EC structure
    set_key = LibECCrypto.EC_KEY_set_private_key(myecc, bn)
    raise "Error could not set private key to EC" unless set_key == 1

    # # ------------
    # # convert binary public key to point
    # eccgrp = LibECCrypto.EC_GROUP_new_by_curve_name(eccgrp_id)
    # raise "Error could not get the group curve" if eccgrp.null?
    # ec_point = LibECCrypto.EC_POINT_new(eccgrp)
    # raise "Error could not create point from group" if ec_point.null?
    #
    # point_res = LibECCrypto.EC_POINT_hex2point(eccgrp, hex_public_key.to_unsafe, ec_point, nil)
    # raise "Error could not get point from public key" if point_res.null?
    #
    # # set the public key on the EC structure
    # set_key = LibECCrypto.EC_KEY_set_public_key(myecc, ec_point)
    # raise "Error could not set public key to EC" unless set_key == 1
    #
    # # ------------

    # sign
    sign_pointer = LibECCrypto.ECDSA_do_sign(message, message.bytesize, myecc)
    raise "Error could not sign message with key" if sign_pointer.null?

    # get the r,s from the signing
    sign_value = sign_pointer.value
    r_hex = LibECCrypto.BN_bn2hex(sign_value.r)
    s_hex = LibECCrypto.BN_bn2hex(sign_value.s)

    r = String.new(r_hex).downcase
    s = String.new(s_hex).downcase

    # Free up mem
    LibECCrypto.EC_KEY_free(myecc)
    # LibECCrypto.BN_clear_free(bn)
    LibECCrypto.ECDSA_SIG_free(sign_pointer)

    {
      r: r,
      s: s,
    }
  end

  # Verifies a signed message with a public key and the signature
  def self.verify(hex_public_key : String, message : String, r : String, s : String)
    # Create a EC key structure, setting the group type from NID
    eccgrp_id = LibECCrypto.OBJ_txt2nid("secp256k1")
    raise "Error could not set EC group" unless eccgrp_id != 0
    myecc = LibECCrypto.EC_KEY_new_by_curve_name(eccgrp_id)
    raise "Error could not create curve" if myecc.null?

    # convert binary public key to point
    eccgrp = LibECCrypto.EC_GROUP_new_by_curve_name(eccgrp_id)
    raise "Error could not get the group curve" if eccgrp.null?
    ec_point = LibECCrypto.EC_POINT_new(eccgrp)
    raise "Error could not create point from group" if ec_point.null?

    point_res = LibECCrypto.EC_POINT_hex2point(eccgrp, hex_public_key.to_unsafe, ec_point, nil)
    raise "Error could not get point from public key" if point_res.null?

    # set the public key on the EC structure
    set_key = LibECCrypto.EC_KEY_set_public_key(myecc, ec_point)
    raise "Error could not set public key to EC" unless set_key == 1

    # convert r,s hex to bn
    r_bn = LibECCrypto.BN_new
    raise "Error could not create a new bn for r" if r_bn.null?
    LibECCrypto.BN_hex2bn(pointerof(r_bn), r)

    s_bn = LibECCrypto.BN_new
    raise "Error could not create a new bn for s" if s_bn.null?
    LibECCrypto.BN_hex2bn(pointerof(s_bn), s)

    # set r,s onto signature
    sig = LibECCrypto::ECDSA_SIG_Struct_setter.new
    sig.r = r_bn
    sig.s = s_bn

    # verify
    result = LibECCrypto.ECDSA_do_verify(message, message.bytesize, pointerof(sig), myecc)

    # Free up mem
    LibECCrypto.EC_KEY_free(myecc)
    LibECCrypto.EC_POINT_free(ec_point)
    LibECCrypto.BN_clear_free(r_bn)
    LibECCrypto.BN_clear_free(s_bn)

    result == 1
  end

  def self.get_public_key_from_private(hex_private_key : String)
    # Create a EC key structure, setting the group type from NID
    eccgrp_id = LibECCrypto.OBJ_txt2nid("secp256k1")
    raise "Error could not set EC group" unless eccgrp_id != 0
    myecc = LibECCrypto.EC_KEY_new_by_curve_name(eccgrp_id)
    raise "Error could not create curve" if myecc.null?

    # Create a group
    eccgrp = LibECCrypto.EC_GROUP_new_by_curve_name(eccgrp_id)
    raise "Error could not get the group curve" if eccgrp.null?

    #  Create an EC_POINT to hold the public_key
    ec_point = LibECCrypto.EC_POINT_new(eccgrp)
    raise "Error could not create point from group" if ec_point.null?

    # Convert hex private key to binary
    bn = LibECCrypto.BN_new
    raise "Error could not create a new bn" if bn.null?
    binary_private_key = LibECCrypto.BN_hex2bn(pointerof(bn), hex_private_key)
    raise "Error private key binary is wrong size" if binary_private_key != 64

    # Do the mul that sets the public key onto ec_point
    mul = LibECCrypto.EC_POINT_mul(eccgrp, ec_point, bn, nil, nil, nil)
    raise "Error could not find public key" unless mul == 1

    # Get the public key in hex
    form = LibECCrypto::PointConversionFormT::PointConversionUncompressed
    public_key_pointer = LibECCrypto.EC_POINT_point2hex(eccgrp, ec_point, form, nil)
    raise "Error could not get the public key pointer" if public_key_pointer.null?

    # Free up mem
    LibECCrypto.EC_KEY_free(myecc)
    LibECCrypto.EC_GROUP_free(eccgrp)
    LibECCrypto.EC_POINT_free(ec_point)
    LibECCrypto.BN_clear_free(bn)

    String.new(public_key_pointer).downcase
  end

  def self.encrypt(hex_receiver_public_key : String, message : String) : String
    dummy : UInt8 = 0
    epubk : UInt8* = pointerof(dummy)
    epubk_len : LibC::SizeT = 0
    iv : UInt8* = pointerof(dummy)
    iv_len : LibC::Int = 0
    tag : UInt8* = pointerof(dummy)
    tag_len : LibC::Int = 0
    ciphertext : UInt8* = pointerof(dummy)
    ciphertext_len : LibC::SizeT = 0

    # set the group type from NID
    eccgrp_id = LibECCrypto.OBJ_txt2nid("secp256k1")
    raise "Error could not set EC group" unless eccgrp_id != 0
    raise "Message must not be empty" unless message.size > 0

    # use the crypto library to encrypt the message using the receiver public key and get the ephemeral public key, the init vector and the tag
    #    (we add one to message size to encrypt the null at the end of the string)
    status = LibECCrypto.encrypt_message(message.bytes, message.size + 1,
      eccgrp_id, hex_receiver_public_key,
      pointerof(epubk), pointerof(epubk_len),
      pointerof(iv), pointerof(iv_len),
      pointerof(tag), pointerof(tag_len),
      pointerof(ciphertext), pointerof(ciphertext_len))
    raise String.new(ciphertext) unless status == 0

    # put the encrypted elements all together into one long hex string that can be transmitted (pieces are separated by 'fx')
    msg = bytes2hex(ciphertext, ciphertext_len) + "fx" + bytes2hex(tag, tag_len) + "fx" + bytes2hex(iv, iv_len) + "fx" + bytes2hex(epubk, epubk_len)
    return msg
  end

  def self.decrypt(hex_receiver_private_key : String, encrypted_message : String) : String
    dummy : UInt8 = 0
    decrypted_message : UInt8* = pointerof(dummy)

    raise "Encrypted message must not be empty" unless encrypted_message.size > 0
    # pull the componente of the encrypted message apart
    chunks = encrypted_message.split("fx")
    raise "Message not encrypted by ECCrypto.encrypt" if chunks.size != 4
    ciphertext_len : LibC::SizeT = (chunks[0].size / 2).to_u64
    ciphertext = hex2bytes(chunks[0])
    tag_len : LibC::Int = (chunks[1].size / 2).to_i
    tag = hex2bytes(chunks[1])
    iv_len : LibC::Int = (chunks[2].size / 2).to_i
    iv = hex2bytes(chunks[2])
    epubk_len : LibC::SizeT = (chunks[3].size / 2).to_u64
    epubk = hex2bytes(chunks[3])

    # set the group type from NID
    eccgrp_id = LibECCrypto.OBJ_txt2nid("secp256k1")
    raise "Error could not set EC group" unless eccgrp_id != 0

    # use the crypto library decrypt the message using the private key, ephemeral public key, init vector and tag
    status = LibECCrypto.decrypt_message(eccgrp_id, hex_receiver_private_key,
      epubk, epubk_len, iv, iv_len, tag, tag_len, ciphertext, ciphertext_len,
      pointerof(decrypted_message))

    raise String.new(decrypted_message) unless status == 0

    return String.new(decrypted_message)
  end

  def self.bytes2hex(the_bytes : UInt8*, the_length : Int) : String
    str = ""
    i = 0
    while i < the_length
      the_hex = the_bytes[i].to_s(16)
      the_hex = "0" + the_hex if the_hex.size == 1
      str += the_hex
      i += 1
    end
    return str
  end

  def self.hex2bytes(hex_string : String) : UInt8*
    str = hex_string
    byte_ptr = Pointer(UInt8).malloc((hex_string.size / 2).to_i)
    i = 0
    while str.size > 0
      digits = str[0..1]
      str = str[2..-1]
      byte_ptr[i] = digits.to_u8(16)
      i += 1
    end
    return byte_ptr
  end
end
