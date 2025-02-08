package utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.bouncycastle.asn1.x509.X509Extensions.ExtendedKeyUsage;

public class JWTUtils {
    private java.security.cert.Certificate[] certificateChain = null;
    private static PrivateKey privateKey = null;
    private PublicKey publicKey = null;
    private Provider pkcs12Provider = null;
    private String keystoreFile = "D:\\Data\\MOBILE_ID\\Demo_sign_PKCS12_JWT\\DemoSignByJWT_PKCS12\\src\\sources\\KeyStorePKCS12";

    private volatile static JWTUtils jwtUtils;


    private JWTUtils() {
    }

    public static JWTUtils getInstance() {
        if (jwtUtils == null) {
            synchronized (JWTUtils.class) {
                if (jwtUtils == null) {
                    jwtUtils = new JWTUtils();
                }
            }
        }

        return jwtUtils;
    }

    public String createJwt(String subject, String issuer, long ttlMillis, String alias, char[] password) throws Exception {
        // Load PKCS#12 keystore
//        KeyStore keystore = KeyStore.getInstance("PKCS12");
//        try (FileInputStream fis = new FileInputStream(keystoreFile)) {
//            keystore.load(fis, null);
//        }

//        keystore.load(JwtUtil.class.getResourceAsStream(keystoreFile), password); bỏ

        // Get private key from keystore
//        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, null);

        // Generate JWT

        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(issuer)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + ttlMillis))
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    public static void createKeyStore (String keystoreFile, String alias, char[] password) throws NoSuchAlgorithmException {
//        // Create a new key pair
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//        keyPairGenerator.initialize(2048); // You can change the key size as needed
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//
//        // Create a self-signed X.509 certificate
//        X509Certificate cert = generationKeyPair_SelfSignedCertificate(alias,keyPair);
//
//        // Store the key pair and certificate in a PKCS#12 keystore
//        KeyStore keyStore = KeyStore.getInstance("PKCS12");
//        keyStore.load(null, null);
//        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, new Certificate[]{cert});
//
//        // Save the keystore to a file
//        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
//            keyStore.store(fos, password);
//        }
    }

    public void generationKeyPair_SelfSignedCertificate(String alias, String information, String extension, String password) throws Exception {
//        KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
//        keyStore.load(null, pin.toCharArray());  // Sử dụng PIN để đăng nhập vào token

        SecureRandom sr = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, sr);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        X509Certificate certificate = generateCertificate(keyPair, information, extension);
        certificateChain = new java.security.cert.Certificate[]{certificate};

        // Store the key pair and certificate in a PKCS#12 keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password.toCharArray());
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), certificateChain);
//        keyStore.store(null, password.toCharArray());
        // Save the keystore to a file
//        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
//            keyStore.store(fos, password.toCharArray());
//        }
    }

    private  X509Certificate generateCertificate(KeyPair keyPair,String information, String extension) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Tạo một chứng chỉ tự ký với Bouncy Castle
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
        X500Name issuerName = new X500Name(information);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000); // Yesterday
        Date endDate = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1 year from now

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                issuerName,
                keyPair.getPublic()
        );

        // Add extensions
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        certificateBuilder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic())
        );
        certificateBuilder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extensionUtils.createAuthorityKeyIdentifier(keyPair.getPublic())
        );
        certificateBuilder.addExtension(
                Extension.basicConstraints,
                true,
                new BasicConstraints(true)
        );
        certificateBuilder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
        );
        certificateBuilder.addExtension(
                Extension.extendedKeyUsage,
                true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
        );
        certificateBuilder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.rfc822Name, extension))
        );

        // Xây dựng chứng chỉ
        X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);

        // Chuyển đổi chứng chỉ holder thành X509Certificate
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter();
        return certificateConverter.getCertificate(certificateHolder);
    }
}
