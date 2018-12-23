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
end
