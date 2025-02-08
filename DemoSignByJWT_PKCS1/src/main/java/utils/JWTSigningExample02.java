package utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

public class JWTSigningExample02 {
    // Sign Data
    String header = "{\"alg\":\"RS256\"}";
    String payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";

    private String filepathPrivateKey = "res/signedAndEncrypted/private_key.pem";
    private String filepathPublicKey = "res/signedAndEncrypted/public_key.pub";

    private volatile static JWTSigningExample02 JWTSigningExample02;

    private JWTSigningExample02() {
    }

    public static JWTSigningExample02 getInstance() {
        if (JWTSigningExample02 == null) {
            synchronized (JWTUtils.class) {
                if (JWTSigningExample02 == null) {
                    JWTSigningExample02 = new JWTSigningExample02();
                    Security.addProvider(new BouncyCastleProvider());
                }
            }
        }

        return JWTSigningExample02;
    }

    public void run() throws Exception {
        // Generate RSA Key Pair
        KeyPair keyPair = generateRSAKeyPair();

        // Extract Private Key
        PrivateKey privateKey = keyPair.getPrivate();

        savePrivateKey(privateKey, filepathPrivateKey);
        savePublicKey(keyPair.getPublic(), filepathPublicKey);

//        CREATE SIGNATURE
        System.out.println("SIGNATURE: " + createSignature(privateKey));
        System.out.println("SIGNATURE_02: " + createSignature2(privateKey));

//        CREATE JWT
        String jwtToken = signData(payload, privateKey);
        System.out.println("JWT SIGNATURE: " + jwtToken.substring(jwtToken.lastIndexOf(".") + 1));
        System.out.println("JWT: " + jwtToken);
    }

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private void savePrivateKey(PrivateKey privateKey, String filename) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename);
             PemWriter pemWriter = new PemWriter(fileWriter)) {

            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
        }
    }

    private void savePublicKey(PublicKey publicKey, String filename) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename);
             PemWriter pemWriter = new PemWriter(fileWriter)) {

            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        }
    }

    private String signData(String data, PrivateKey privateKey) throws JOSEException {
        // Create RSA Signer
        JWSSigner signer = new RSASSASigner(privateKey);

        // Create JWS Header
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();

        // Create JWS Object
        Payload payload = new Payload(data);
        JWSObject jwsObject = new JWSObject(header, payload);

        // Sign JWS Object
        jwsObject.sign(signer);

        // Serialize JWS Object to compact form
        return jwsObject.serialize();
    }

//    Tạo chữ ký số (signature) từ dữ liệu (payload) (Hash and Sign trong 1 bước)
    private String createSignature(PrivateKey privateKey) throws Exception {
        String dataToSign = base64UrlEncode(header) + "." + base64UrlEncode(payload);
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(dataToSign.getBytes("UTF-8"));
        byte[] signatureBytes = signature.sign();
        return Base64.getUrlEncoder().encodeToString(signatureBytes);
//        return Base64.getEncoder().encodeToString(signatureBytes);
    }

//    Tạo chữ ký số (signature) từ dữ liệu (payload) (Hash and Sign trong 2 bước)
//    tham khảo: https://stackoverflow.com/questions/69750026/create-sha256withrsa-in-two-steps
    private String createSignature2(PrivateKey privateKey) throws Exception {
    //        Hash the data using SHA-256
        String dataToHash = base64UrlEncode(header) + "." + base64UrlEncode(payload);
        byte[] hashedBytes = hashDataWithsha256(dataToHash.getBytes("UTF-8"));
        byte[] paddingHashBytes = padding(hashedBytes);

    //        Sign the hashed data using RSA private key
        Signature signature = Signature.getInstance("NONEwithRSA", "BC");
        signature.initSign(privateKey);
        signature.update(paddingHashBytes);
        byte[] signatureBytes = signature.sign();

    //        Encode the signature as Base64 URL-safe string
        return Base64.getUrlEncoder().encodeToString(signatureBytes);
    }

    public String base64UrlEncode(String input) {
        return Base64.getUrlEncoder().encodeToString(input.getBytes())
                .replaceAll("=", "");
    }

//    Method to compute SHA-256 hash
    public static byte[] hashDataWithsha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }
//    PADDING
    public static byte[] padding(byte[] hashBytes) throws Exception {
        //PREPARE PADDING
        byte[] padding = null;
        padding = new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

        //ADD PADDING & HASH TO RESULTING ARRAY
        byte[] paddingHash = new byte[padding.length + hashBytes.length];
        System.arraycopy(padding, 0, paddingHash, 0, padding.length);
        System.arraycopy(hashBytes, 0, paddingHash, padding.length, hashBytes.length);

        //RETURN HASH
        return paddingHash;
    }
}
