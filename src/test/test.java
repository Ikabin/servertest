package test;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Scanner;

import org.bouncycastle.operator.OperatorCreationException;

import CerificatesAndKeys.KeysAndCertificates;
import CerificatesAndKeys.KeysAndCertificates_short;






public class test {
	
	public static void main(String[] args) throws Exception {
		
		Date date = new Date();
		int a = 0;
		int b = 0;
		String userIP = "127.0.0.1";
		String dn = "CN=" + userIP +", OU=SY, O=IHP, L=FFO, ST=Brandenburg, C=DE";
		String rsaalgorithm = "SHA1withRSA";
		String token = "127001";
		String receivedToken = "127001";
		X509Certificate certUser = null;
		
		
		
	    //create selfsigned Certificate for Trusted Center(CA), based on generated caKeyPair
//		int userscurve = 256;
		int CAcurve = 256;
		long longvalue2 = 1234567890;
	    String algorithm = "SHA1withECDSA";
        KeyPair caKeyPair = KeysAndCertificates.generateKeypair(CAcurve, longvalue2);
        String dnCA = "CN=IHP_CA, OU=CY, O=IHP, L=FFO, ST=Brandenburg, C=DE";
		X509Certificate certCA = KeysAndCertificates_short.generateCertificate(dnCA, caKeyPair, 365, algorithm );
		PrivateKey privateCAKey = caKeyPair.getPrivate(); 
		
		
        //RSA CA's certificate
        KeyPairGenerator rsakpg = KeyPairGenerator.getInstance("RSA");
        rsakpg.initialize(2048);
        KeyPair rsakp = rsakpg.genKeyPair();
        PrivateKey rsaprivkey = rsakp.getPrivate();
//        PublicKey rsapubkey = rsakp.getPublic();
        X509Certificate rsaCAcert = KeysAndCertificates_short.generateCertificate(dnCA, rsakp, 365, rsaalgorithm);
        File rsaCAcertout = new File("C:/EB_RSACACERT.cer"); 
        KeysAndCertificates.exportCert(rsaCAcert, rsaCAcertout);

		
		
		System.out.println("CA registration started");
		while (b == 0){
			a = question0();
			question1(a);
			b = question2(b);
		}
		certUser = certificateSelection(a, dn, rsaalgorithm, userIP);
		
		System.out.println("Connecting to CA server...");
		System.out.println("Connection to CA server was successful at " + date.toString());
		System.out.println("Sending registration data from " + userIP + " to CA...");
		question3a(a, token, receivedToken, userIP, date, certUser, certCA, privateCAKey, certUser, rsaCAcert, rsaprivkey);
		//System.out.println("received token: " + receivedToken);
		//caAgencySelection(a, token, receivedToken, userIP, date, certUser, certCA, privateCAKey, certUser, rsaCAcert, rsaprivkey);
		
		System.out.println();
		System.out.println("CA registration finished. Goodbye." );
			
		
		
	}
	
	
	public static int question0(){
		System.out.println("Choose certificate type: HW (1) or USER (2)");
		Scanner s = new Scanner(System.in);
		int a = s.nextInt();
		s.close();
		return a;
	}
	
	
	public static void question1(int a){

		switch(a){
		case 1:	
			System.out.println("You have chosen HW certificate generation. Do You want to continue? (yes/no)");
			break;
		case 2:
			System.out.println("You have chosen USER certificate generation. Do You want to continue? (yes/no)");
			break;
		}
	}
	
	public static int question2(int b){
		Scanner s1 = new Scanner(System.in);
		String a1 = s1.nextLine();
		switch(a1){
		case "yes":
			System.out.println("Certificate generation started");
			b = 1;
			break;
		case "no":
			b = 0;
			break;
		}
		s1.close();
		return b;
	}
	
	
	public static X509Certificate certificateSelection(int a, String dn, String rsaalgorithm, String userIP) throws Exception{
		X509Certificate UC = null;
		switch (a){
		case 1://RSA
			KeyPairGenerator rsakpguser = KeyPairGenerator.getInstance("RSA");
	        rsakpguser.initialize(2048);
	        KeyPair rsakpuser = rsakpguser.genKeyPair();
//	        PrivateKey rsaprivkeyuser = rsakpuser.getPrivate();
	        PublicKey rsapubkeyuser = rsakpuser.getPublic();
	        System.out.println("PublicKey for " + userIP + ": " + rsapubkeyuser);
	        X509Certificate rsaUsercert = KeysAndCertificates_short.generateCertificate(dn, rsakpuser, 365, rsaalgorithm);
	//        System.out.println("HW Cerificate for " + userIP +" was generated:");
	//        System.out.println(rsaUsercert);
	        UC = rsaUsercert;
			break;
		case 2://ECC
			int userscurve = 256;
//			int CAcurve = 256;
			
		    //create selfsigned Certificate for customer, based on generated userKeyPair
			long longvalue1 = 1234567;
	        KeyPair userKeyPair = KeysAndCertificates.generateKeypair(userscurve, longvalue1);
		    String algorithm = "SHA1withECDSA";
		    X509Certificate certUser = KeysAndCertificates_short.generateCertificate(dn, userKeyPair, 365, algorithm );
//		    PrivateKey privateUserKey = userKeyPair.getPrivate();
		    PublicKey pubUserKey = userKeyPair.getPublic();
		    System.out.println("PublicKey for " + userIP + ": " + pubUserKey);
	   //     System.out.println("USER Cerificate for " + userIP +" was generated:");
	    //    System.out.println(certUser);
	        UC = certUser;
	        break;
		}
		return UC;
	}
	
	
	
	
	
	public static void caAgencySelection(int a, String token, String receivedToken, String userIP, Date date, X509Certificate certUser, X509Certificate certCA, PrivateKey privateCAKey,
																								X509Certificate rsaUsercert, X509Certificate rsaCAcert, PrivateKey rsaprivkey) throws OperatorCreationException, CertificateException, IOException{
		switch(a){
		case 1:
			
		//	tokenVerificationRSA(token, receivedToken, userIP, date, certUser, certCA, privateCAKey);
			if (receivedToken == token){
				X509Certificate signedRSACertificate = KeysAndCertificates_short.createSignedCertificate(rsaUsercert, rsaCAcert, rsaprivkey);
				System.out.println("Registration of HW Certificate for " + userIP + " was successful at "+ date);
				System.out.println("Credential for " + userIP + " saved.");
				System.out.println("Your HW signed Certificate: " + signedRSACertificate);
				
			}
			else{
				System.out.println("Registration of HW Certificate for " + userIP + " failed. \n Token doesn't match.");
			}
			break;
		case 2:
	//		tokenVerificationEC(token, receivedToken, userIP, date, rsaUsercert, rsaCAcert, rsaprivkey);
			if (receivedToken == token){
				X509Certificate signedCertificate = KeysAndCertificates_short.createSignedCertificate(certUser, certCA, privateCAKey);
				System.out.println("Registration of USER Certificate for " + userIP + " was successful at "+ date);
				System.out.println("Credential for " + userIP + " saved.");
				System.out.println("Your USER signed Certificate: " + signedCertificate);
				
			}
			else{
				System.out.println("Registration of USER Certificate for " + userIP + " failed. \n Token doesn't match.");
			}
			break;
		}
	}
	
	
	
	public static String question3(){
		System.out.println("Enter your token:");
		Scanner s1 = new Scanner(System.in);
		String a1 = s1.nextLine();
		System.out.println("token --> " + a1);
		s1.close();
		return a1;
	}
	
	
	public static void question3a(int a, String token, String receivedToken, String userIP, Date date, X509Certificate certUser, X509Certificate certCA, PrivateKey privateCAKey,
																										X509Certificate rsaUsercert, X509Certificate rsaCAcert, PrivateKey rsaprivkey) throws OperatorCreationException, CertificateException, IOException{
		System.out.println("Enter your token:");
		Scanner s1 = new Scanner(System.in);
		String a1 = s1.nextLine();
		switch(a1){
		case "127001":
			caAgencySelection(a, token, receivedToken, userIP, date, certUser, certCA, privateCAKey, certUser, rsaCAcert, rsaprivkey);
			
			break;
		default:
			System.out.println("Registration of USER Certificate for " + userIP + " failed. \n Token doesn't match.");
			break;
		}
		s1.close();
	}
	
	
	
	public static void tokenVerificationEC(String token, String receivedToken, String userIP, Date date, X509Certificate certUser, X509Certificate certCA, PrivateKey privateCAKey) throws OperatorCreationException, CertificateException, IOException{
		if (receivedToken == token){
			X509Certificate signedCertificate = KeysAndCertificates_short.createSignedCertificate(certUser, certCA, privateCAKey);
			System.out.println("Registration of USER Certificate for " + userIP + " was successful at "+ date);
			System.out.println("Credential for " + userIP + " saved.");
			System.out.println("Your USER signed Certificate: " + signedCertificate);
			
		}
		else{
			System.out.println("Registration of USER Certificate for " + userIP + " failed. \n Token doesn't match.");
		}
		
	}
	
	public static void tokenVerificationRSA(String token, String receivedToken, String userIP, Date date, X509Certificate rsaUsercert, X509Certificate rsaCAcert, PrivateKey rsaprivkey) throws OperatorCreationException, CertificateException, IOException{
		if (receivedToken == token){
			X509Certificate signedRSACertificate = KeysAndCertificates_short.createSignedCertificate(rsaUsercert, rsaCAcert, rsaprivkey);
			System.out.println("Registration of HW Certificate for " + userIP + " was successful at "+ date);
			System.out.println("Credential for " + userIP + " saved.");
			
			System.out.println("Your HW signed Certificate: " + signedRSACertificate);
			
		}
		else{
			System.out.println("Registration of HW Certificate for " + userIP + " failed. \n Token doesn't match.");
		}
		
	}
	
	

}
