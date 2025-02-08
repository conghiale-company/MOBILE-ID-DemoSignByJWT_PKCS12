package org.example;

import utils.JWTUtils;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

/**
 * Hello world!
 *
 */
public class App 
{


    public static void main( String[] args ) throws Exception {
        String configFilePath = "C:/WINDOWS/System32/eps2003csp11.dll";  // Đường dẫn tới file cấu hình PKCS#11
        String password = "12345678";  // Mật khẩu

        String issuerCommonName = "Travel App";
        String certificateSerialNumber = "1713253906839";
        String location = "LOCATION";
        String alias = "Conghiale";
        String infomation = "UID=CMND:12345678, CN=Lê Công Nghĩa, ST=Bình Thuận, C=VN";
        String extension = "Conghiale@gmail.com";

        System.out.println( "Create keystore" );
        JWTUtils.getInstance().generationKeyPair_SelfSignedCertificate(alias, infomation, extension, password);
        System.out.println();

        System.out.println( "Create a signature" );
        String jwt = JWTUtils.getInstance().createJwt(infomation, issuerCommonName, 3600000, alias, password.toCharArray());
        System.out.println("JWT created: ----------- ");
        System.out.println(jwt);
    }
}
