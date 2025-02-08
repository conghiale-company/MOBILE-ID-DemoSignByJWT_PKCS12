package utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.util.Base64;
import java.util.Date;

public class JWTSignatureExample {
    String dataToSign = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";
    private volatile static JWTSignatureExample JWTSignatureExample;

    private JWTSignatureExample() {
    }

    public static JWTSignatureExample getInstance() {
        if (JWTSignatureExample == null) {
            synchronized (JWTUtils.class) {
                if (JWTSignatureExample == null) {
                    JWTSignatureExample = new JWTSignatureExample();
                }
            }
        }

        return JWTSignatureExample;
    }

    public void run() throws Exception {
        // Generate RSA Key Pair
        KeyPair keyPair = generateRSAKeyPair();

        // Create JWT Claims
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("name", "John Doe")
                .claim("admin", true)
//                .issuer("https://example.com")
                .subject("1234567890")
//                .expirationTime(new Date(System.currentTimeMillis() + 3600 * 1000)) // Expire in 1 hour
                .build();

//        CREATE SIGNATURE
        System.out.println("SIGNATURE: " + createSignature(dataToSign, keyPair.getPrivate()));

        // Sign JWT
        SignedJWT signedJWT = signJWT(claimsSet, keyPair.getPrivate());

        // Serialize JWT to compact form
        String compactJWT = signedJWT.serialize();
        System.out.println("Signed JWT: " + compactJWT.substring(compactJWT.lastIndexOf(".") + 1));
    }

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private SignedJWT signJWT(JWTClaimsSet claimsSet, PrivateKey privateKey) throws JOSEException {
        // Create RSA Signer
        JWSSigner signer = new RSASSASigner(privateKey);

        // Create JWS Header
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();

        // Create JWS Object
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        // Sign JWT
        signedJWT.sign(signer);

        return signedJWT;
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
