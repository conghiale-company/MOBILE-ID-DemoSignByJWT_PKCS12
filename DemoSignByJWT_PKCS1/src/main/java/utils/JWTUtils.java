package utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static utils.PemUtils.*;

public class JWTUtils {
    String dataToSign = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";

    private String filepathPrivateKey = "res/signedAndEncrypted/signing_private_key_in_pkcs8.pem";
    private String filepathPublicKey = "res/signedAndEncrypted/signing_public.pub";
    private String filepathEncryptPrivateKey = "res/signedAndEncrypted/encrypt_private_key_in_pkcs8.pem";
    private String filepathEncryptPublicKey = "res/signedAndEncrypted/encrypt_public.pub";
    private String filepathAESeKey = "res/signedAndEncrypted/AES_key_in_pkcs8.pem";

    private RSAPrivateKey encryptPrivateKey;
    private SecretKey secretKey;
    private
    Algorithm algorithm;

    private volatile static JWTUtils jwtUtils;

    private JWTUtils() {
    }

    public static JWTUtils getInstance() {
        if (jwtUtils == null) {
            synchronized (JWTUtils.class) {
                if (jwtUtils == null) {
                    jwtUtils = new JWTUtils();
                    Security.addProvider(new BouncyCastleProvider());
                }
            }
        }

        return jwtUtils;
    }

//    1. Creating keys for signing:
    public void createKeysForSigning() throws Exception {

        // Bước 1: Tạo cặp khóa RSA
        KeyPair keyPair = generateRSAKeyPair();

        // Bước 2: Lưu khóa riêng tư dưới dạng PKCS8
        savePrivateKeyAsPKCS8(keyPair.getPrivate(), filepathPrivateKey);

        // Bước 3: Lưu khóa công khai
        savePublicKey(keyPair.getPublic(), filepathPublicKey);
    }

    private KeyPair generateRSAKeyPair() throws Exception {
        SecureRandom sr = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048, sr);
//        keyPairGenerator.initialize(512); // Độ dài của khóa RSA

        return keyPairGenerator.generateKeyPair();
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
//        generator.initialize(512); // Độ dài của khóa RSA
//        return generator.generateKeyPair();
    }

    private static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    private void savePrivateKeyAsPKCS8(PrivateKey privateKey, String filename) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename);
             PemWriter pemWriter = new PemWriter(fileWriter)) {

            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
        }
    }

    private static void saveAESKeyAsPKCS8(byte[] aesKeyBytes, String filename) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename);
             PemWriter pemWriter = new PemWriter(fileWriter)) {

            PemObject pemObject = new PemObject("AES KEY", aesKeyBytes);
            pemWriter.writeObject(pemObject);
        }
    }

    private void savePublicKey(PublicKey publicKey, String filename) throws IOException {
        try (FileWriter fileWriter = new FileWriter(filename);
             PemWriter pemWriter = new PemWriter(fileWriter)) {

            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        }
    }

//    2. Create JWT and sign it
    public String createJWTAndSign() throws Exception {
        RSAPrivateKey signingPrivateKey = (RSAPrivateKey) readPrivateKeyFromFile(filepathPrivateKey, "RSA");
        RSAPublicKey signingPublicKey = (RSAPublicKey) readPublicKeyFromFile(filepathPublicKey, "RSA");
        RSAKeyProvider provider = new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String s) {
                return signingPublicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return signingPrivateKey;
            }

            @Override
            public String getPrivateKeyId() {
                return "MID_28102002";
            }
        };

        algorithm = Algorithm.RSA256(provider);

//        return JWT.create()
//                .withIssuer("auth0")
//                .withSubject("UID=CMND:12345678, CN=Lê Công Nghĩa, ST=Bình Thuận, C=VN")
//                .withClaim("name", "Bob")
//                .sign(algorithm);


        PrivateKey privateKey = readPrivateKeyFromFile(filepathPrivateKey, "RSA");
        PublicKey publicKey = readPublicKeyFromFile(filepathPublicKey, "RSA");

//        CREATE SIGNATURE
        System.out.println("SIGNATURE: " + createSignature(dataToSign, privateKey));

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "1234567890");
        claims.put("name", "John Doe");
        claims.put("admin", true);

        return Jwts.builder()
                .setClaims(claims)
//                .setSubject("UID=CMND:12345678, CN=Lê Công Nghĩa, ST=Bình Thuận, C=VN")
//                .setIssuer("Travel App")
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

//    3. Creating keys for encryption:
    public void createKeysForEncryption() throws Exception {

        // Bước 1: Tạo cặp khóa RSA
        KeyPair keyPair = generateRSAKeyPair();

        // Generate AES key
        SecretKey aesKey = generateAESKey();

        // Bước 2: Lưu khóa riêng tư dưới dạng PKCS8
        savePrivateKeyAsPKCS8(keyPair.getPrivate(), filepathEncryptPrivateKey);

        // Bước 3: Lưu khóa AES
        // Encrypt AES secret key with RSA public key
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.WRAP_MODE, keyPair.getPublic());

        byte[] encryptedSecretKey = rsaCipher.wrap(aesKey);
        saveAESKeyAsPKCS8(encryptedSecretKey, filepathAESeKey);

        // Bước 4: Lưu khóa công khai
        savePublicKey(keyPair.getPublic(), filepathEncryptPublicKey);
    }

//    4. Encrypt signed JWT (implementation from https://www.baeldung.com/java-rsa)
    public byte[] encryptSignedJWT(String signedToken) throws Exception {
        encryptPrivateKey = (RSAPrivateKey) readPrivateKeyFromFile(filepathEncryptPrivateKey, "RSA");
        RSAPublicKey encryptPublicKey = (RSAPublicKey) readPublicKeyFromFile(filepathEncryptPublicKey, "RSA");
        secretKey = readAESKeyFromFile(filepathAESeKey);

//        Decrypt AES secret key with RSA private key
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.UNWRAP_MODE, encryptPrivateKey);
        SecretKey decryptedSecretKey = (SecretKey) rsaCipher.unwrap(secretKey.getEncoded(), "AES", Cipher.SECRET_KEY);

        // Encrypt data with AES
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, decryptedSecretKey);
        byte[] secretMessageBytes = signedToken.getBytes(StandardCharsets.UTF_8);
        return aesCipher.doFinal(secretMessageBytes);

//        Cipher encryptCipher = Cipher.getInstance("RSA");
//        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptPublicKey);

    }

//    5. Decrypt signed JWT
    public byte[] decryptSignedJWT(byte[] encryptedMessageBytes) throws Exception {
//        Cipher decryptCipher = Cipher.getInstance("RSA");
//        decryptCipher.init(Cipher.DECRYPT_MODE, encryptPrivateKey);

        encryptPrivateKey = (RSAPrivateKey) readPrivateKeyFromFile(filepathEncryptPrivateKey, "RSA");
        RSAPublicKey encryptPublicKey = (RSAPublicKey) readPublicKeyFromFile(filepathEncryptPublicKey, "RSA");
        secretKey = readAESKeyFromFile(filepathAESeKey);

//        Decrypt AES secret key with RSA private key
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.UNWRAP_MODE, encryptPrivateKey);
        SecretKey decryptedSecretKey = (SecretKey) rsaCipher.unwrap(secretKey.getEncoded(), "AES", Cipher.SECRET_KEY);

//        Decrypt data with decrypted AES secret key
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, decryptedSecretKey);
        return aesCipher.doFinal(encryptedMessageBytes);
    }

//    6. Verify JWT
    public void verifyJWT(byte[] decryptedSignedToken) {
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth0")
                .withClaim("name", "Bob")
                .build();

        verifier.verify(Arrays.toString(decryptedSignedToken));
    }

//    Tạo chữ ký số (signature) từ dữ liệu (payload)
    private static String createSignature(String payload, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(payload.getBytes());
        byte[] signatureBytes = signer.sign();

        // Encode signature thành chuỗi Base64
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
}
