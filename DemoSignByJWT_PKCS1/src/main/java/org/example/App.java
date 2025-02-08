package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.JWTSignatureExample;
import utils.JWTSigningExample02;
import utils.JWTUtils;
import utils.Nimbus_JOSE_JWT;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static utils.PemUtils.readPrivateKeyFromFile;
import static utils.PemUtils.readPublicKeyFromFile;

/**
 * Hello world!
 *
 */
public class App 
{
    // Your JWT Payload
    private static String header = "{\"alg\":\"RS256\"}";
    private static String payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";

    private static String filepathPrivateKey = "res/signedAndEncrypted/private_key.pem";
    private static String filepathPublicKey = "res/signedAndEncrypted/public_key.pub";

    public static void main( String[] args ) throws Exception {
//        runJWTUtils();
//        runNimbus_JOSE_JWT();
//        runJWTSignatureExample();
        runJWTSignatureExample2();
//        runJWTSignature();
    }

    private static void runJWTSignatureExample2() throws Exception {
        JWTSigningExample02.getInstance().run();
    }

    private static void runJWTSignature() throws Exception {
        // Add Bouncy Castle Provider
        Security.addProvider(new BouncyCastleProvider());

        PrivateKey privateKey = readPrivateKeyFromFile(filepathPrivateKey, "RSA");
        PublicKey publicKey = readPublicKeyFromFile(filepathPublicKey, "RSA");

        // Sign JWT
        String jwtToken = signJWT(privateKey);
        System.out.println("JWT Token: " + jwtToken);

        // Verify JWT
        jwtToken = "fICuvLEYNORf5zg8ks7-L-fBt9EASdmcEpIxD860e-2Y8oBddV946xUINNgGqnWJyQrb1Swcb2thNvsUKkzmS1JxRAlHiH9I-l8nEgVu8zLUeurrqPpp5BYQJ8DsHI-BapEtmgm5XhN0BN9dophnCNKjq-ltvpKCp7Fz08HlWaAlJLcYS2hCKtZEHwILJ3U9ti0pEYBE8Z2AImiNsQCxOx0h3oQoArhwhgaLxG-8ftsZWN7G7-IsN3q8iGGnHJ5OQ-TuTfqPa6Exh9TCGmPDNGn6ddMHPRVgkf61ENdNfEDiUAR3NHist94P-U2DpyFTIRwZKAzWvM3N2k00cq-irw";
        boolean isValid = verifyJWT(jwtToken, publicKey);
        System.out.println("Is JWT Valid? " + isValid);
    }

    public static boolean verifyJWT(String jwtToken, PublicKey publicKey) throws Exception {
//        byte[] signatureBytes = Base64.getUrlDecoder().decode(jwtToken);
//
//        Signature signature = Signature.getInstance("SHA256withRSAandMGF1", "BC");
//        signature.initVerify(publicKey);
//        signature.update(jwtPayload.getBytes("UTF-8"));
//
//        // Verify JWT signature
//        return signature.verify(signatureBytes);
//
        // Decode JWT signature
        byte[] signatureBytes = Base64.getUrlDecoder().decode(jwtToken);
        String dataToSign = base64UrlEncode(header) + "." + base64UrlEncode(payload);

        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initVerify(publicKey);
        signature.update(dataToSign.getBytes("UTF-8"));

        // Verify JWT signature
        return signature.verify(signatureBytes);
    }

    public static String signJWT(PrivateKey privateKey) throws Exception {
//        Chuỗi dữ liệu cần ký
        String dataToSign = base64UrlEncode(header) + "." + base64UrlEncode(payload);
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(dataToSign.getBytes("UTF-8"));
        byte[] signatureBytes = signature.sign();
        return Base64.getUrlEncoder().encodeToString(signatureBytes);
    }

    private static void runJWTSignatureExample() throws Exception {
        JWTSignatureExample.getInstance().run();
    }

    private static void runNimbus_JOSE_JWT() throws Exception {
        Nimbus_JOSE_JWT.getInstance().run();
    }

    private static void runJWTUtils() throws Exception {
        String signedToken;
        byte[] encryptedMessageBytes;
        byte[] decryptedMessageBytes;

//        1. Creating keys for signing:
        JWTUtils.getInstance().createKeysForSigning();

//        2. Create JWT and sign it
        signedToken = JWTUtils.getInstance().createJWTAndSign();

//        3. Creating keys for encryption:
        JWTUtils.getInstance().createKeysForEncryption();
        System.out.println();
        System.out.println("JWT Token = " + signedToken.substring(signedToken.lastIndexOf(".") + 1));
        System.out.println("SIGNED MESSAGE = " + signedToken);

//        4. Encrypt signed JWT
        encryptedMessageBytes = JWTUtils.getInstance().encryptSignedJWT(signedToken);

//        5. Decrypt signed JWT
        decryptedMessageBytes = JWTUtils.getInstance().decryptSignedJWT(encryptedMessageBytes);

//        6. Verify JWT
//        JWTUtils.getInstance().verifyJWT(decryptedMessageBytes);

        String decryptedSignedToken = new String(decryptedMessageBytes, StandardCharsets.UTF_8);
        String encryptedSignedToken = new String(encryptedMessageBytes, StandardCharsets.UTF_8);

//        System.out.println();
//        System.out.println("ENCRYPTED MESSAGE = " + encryptedSignedToken);
//        System.out.println();
//        System.out.println("DECRYPTED MESSAGE = " + decryptedSignedToken);
    }

    public static String base64UrlEncode(String input) {
        return Base64.getUrlEncoder().encodeToString(input.getBytes())
                .replaceAll("=", "");
    }
}
