require "openssl"
require "secp256k1"
require "./lib_eccrypto"

module ECCrypto
  # Creates a Key Pair
  def self.create_key_pair
    # Create the public/private EC key pair
    key_pair = Secp256k1::Keypair.new
    raise "Error could not generate an EC public/private key pair" if key_pair.nil?

    #  Get the private key
    private_key = key_pair.get_secret
    raise "Error could not get the private key" if private_key.nil?

    # Get the public key
    ec_point = key_pair.public_key
    raise "Error could not get the public ec point" if ec_point.nil?
    public_key = Secp256k1::Util.public_key_uncompressed_prefix ec_point
    raise "Error could not get the public key" if public_key.nil?

    # Retry if the keypair appears invalid
    return create_key_pair if private_key.hexbytes? == nil || private_key.size != 64
    return create_key_pair if public_key.hexbytes? == nil || public_key.size != 130

    {
      hex_private_key: private_key,
      hex_public_key:  public_key,
    }
  end

  def self.sha256(base : Bytes | String) : String
    Secp256k1::Hash.sha256 base
  end

  # Signs a message with a private key
  def self.sign(hex_private_key : String, message : String)
    # set signing algo ### @TODO check algo used
    # ## LibECCrypto.EC_KEY_set_asn1_flag(myecc, 1)
    raise "Error private key binary is wrong size" if hex_private_key.size != 64

    # sign
    signature = Secp256k1::Signature.sign message, BigInt.new(hex_private_key, 16)
    raise "Error could not sign message with key" if signature.nil?

    # get the r,s from the signing
    r = Secp256k1::Util.to_padded_hex_32 signature.r
    s = Secp256k1::Util.to_padded_hex_32 signature.s

    {
      r: r,
      s: s,
    }
  end

  # Verifies a signed message with a public key and the signature
  def self.verify(hex_public_key : String, message : String, r : String, s : String)
    # convert hex public key to point
    point_res = Secp256k1::Util.restore_public_key hex_public_key
    raise "Error could not get point from public key" if point_res.nil?

    # verify
    signature = Secp256k1::ECDSASignature.new BigInt.new(r, 16), BigInt.new(s, 16)
    result = Secp256k1::Signature.verify(message, signature, point_res)

    result == 1
  end

  def self.get_public_key_from_private(hex_private_key : String)
    ec_point = Secp256k1::Util.public_key_from_private BigInt.new(hex_private_key, 16)
    Secp256k1::Util.public_key_uncompressed_prefix ec_point
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
