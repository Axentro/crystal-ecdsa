require "./spec_helper"

describe ECCrypto do
  private_key = "121bf4576133a1b57f6b4bbd30569de01b6fbe918d9b9de27b5c6dd345808c49"
  public_key = "047f4e40cf81797df698c3673b9d27c72ade67e2cd68f309230ac2971cea04c80f8419d7804eb380afbcab569c22d8e64caaf2d7c60799ae9bd2504aa6303a244f"

  it "should generate a public/private keypair" do
    key_pair = ECCrypto.create_key_pair
    key_pair[:hex_private_key].size.should eq(64)
    key_pair[:hex_public_key].size.should eq(130)
  end

  describe "Signing" do
    it "should sign a message using the private key" do
      message = ECCrypto.sha256("this message is being signed")
      sig = ECCrypto.sign(private_key, message)
      sig["r"].nil?.should be_false
      sig["s"].nil?.should be_false
    end

    it "should raise an error if the private key is of wrong length" do
      message = ECCrypto.sha256("this message is being signed")
      expect_raises(Exception, "Error private key binary is wrong size") do
        ECCrypto.sign("fdasf", message)
      end
    end
  end

  describe "Verify" do
    it "should successfully verify a signed message using the public key and signature" do
      message = ECCrypto.sha256("this message is being signed")
      sig = ECCrypto.sign(private_key, message)
      result = ECCrypto.verify(public_key, message, sig["r"], sig["s"])
      result.should be_true
    end

    it "should return false if can't verify a signed message using the public key and signature" do
      message = ECCrypto.sha256("this message is being signed")
      sig = ECCrypto.sign(private_key, message)
      public_key = ECCrypto.create_key_pair[:hex_public_key]
      result = ECCrypto.verify(public_key, message, sig["r"], sig["s"])
      result.should be_false
    end

    it "should return false if can't verify a signed message when using a different message" do
      message = ECCrypto.sha256("this message is being signed")
      different_message = ECCrypto.sha256("this is a different message")
      sig = ECCrypto.sign(private_key, message)
      result = ECCrypto.verify(public_key, different_message, sig["r"], sig["s"])
      result.should be_false
    end

    it "should return error if invalid public key" do
      message = ECCrypto.sha256("this message is being signed")
      sig = ECCrypto.sign(private_key, message)
      expect_raises(Exception, "Error could not get point from public key") do
        ECCrypto.verify("whatever", message, sig["r"], sig["s"])
      end
    end
  end

  describe "get_public_key_from_private" do
    it "should get a public key from a private key" do
      key_pair = ECCrypto.create_key_pair
      private_key = key_pair[:hex_private_key]
      expected_public_key = key_pair[:hex_public_key]
      public_key = ECCrypto.get_public_key_from_private(private_key)
      public_key.should eq(expected_public_key)
    end
  end

  describe "Encryption and decryption of a message" do
    it "should encrypt a message to a ciphertext and decrypt the same message from the ciphertext" do
      assert_encrypt_decrypt
    end

    it "should encrypt a message (larger than 256 bytes) to a ciphertext and decrypt the same message from the ciphertext" do
      message = "This is a test of the emergency broadcast system.\n"
      message += "If this were an actual emergency, you would be instructed to put your head between you legs and kiss your ass goodbye.\n"
      message += "This is a test of the emergency broadcast system.\n"
      message += "If this were an actual emergency, you would be instructed to put your head between you legs and kiss your ass goodbye.\n"

      assert_encrypt_decrypt(message)
    end
  end

  describe "Encrypt errors" do
    it "should raise an error on invalid public key" do
      message = "This is a test, you really should study"
      expect_raises(Exception, "Invalid public key") do
        ECCrypto.encrypt("xxyyxzz", message)
      end
    end

    it "should raise an error on empty message" do
      expect_raises(Exception, "Message must not be empty") do
        receiver_public_key = ECCrypto.create_key_pair[:hex_public_key]
        ECCrypto.encrypt(receiver_public_key, "")
      end
    end
  end

  describe "Decrypt errors" do
    it "should raise an error on invalid private key" do
      receiver_key_pair = ECCrypto.create_key_pair
      receiver_public_key = receiver_key_pair[:hex_public_key]
      message = "This is a test, you really should study"
      encrypted_message = ECCrypto.encrypt(receiver_public_key, message)
      expect_raises(Exception, "Invalid private key") do
        ECCrypto.decrypt("xxyyxzz", encrypted_message)
      end
    end

    it "should raise an error on valid but non matching private" do
      receiver_key_pair = ECCrypto.create_key_pair
      receiver_public_key = receiver_key_pair[:hex_public_key]
      non_matching_private_key = ECCrypto.create_key_pair[:hex_private_key]
      message = "This is a test, you really should study"
      encrypted_message = ECCrypto.encrypt(receiver_public_key, message)

      expect_raises(Exception, "Decryption verification failed") do
        ECCrypto.decrypt(non_matching_private_key, encrypted_message)
      end
    end

    it "should raise an error on empty decrypt message" do
      receiver_private_key = ECCrypto.create_key_pair[:hex_private_key]

      expect_raises(Exception, "Encrypted message must not be empty") do
        ECCrypto.decrypt(receiver_private_key, "")
      end
    end

    it "should raise an error when encrypted message was not encrypted by this library" do
      receiver_key_pair = ECCrypto.create_key_pair
      receiver_private_key = receiver_key_pair[:hex_private_key]
      expect_raises(Exception, "Message not encrypted by ECCrypto.encrypt") do
        ECCrypto.decrypt(receiver_private_key, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbb")
      end
    end
  end
end

private def assert_encrypt_decrypt(message = "This is a test, you really should study")
  receiver_key_pair = ECCrypto.create_key_pair
  receiver_public_key = receiver_key_pair[:hex_public_key]
  receiver_private_key = receiver_key_pair[:hex_private_key]
  encrypted_message = ECCrypto.encrypt(receiver_public_key, message)
  decrypted_message = ECCrypto.decrypt(receiver_private_key, encrypted_message)
  decrypted_message.should eq(message)
end
