package CerificatesAndKeys;



import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import java.nio.file.*;
import CerificatesAndKeys.KeysAndCertificates_short;


public class MyMain {

	public static PrivateKey rootPrivateKeyEC;
	public static X509Certificate rootCertificateEC;
	
	public static PrivateKey rootPrivateKeyRSA;
	public static X509Certificate rootCertificateRSA;
	
	public static String aliasEC = "rootEC";
	public static String aliasRSA = "rootRSA";	
	
	public static void main(String[] args) throws Exception {
	
		final String keystorePathString = "C:/CommunicationTest/CA/rootKeystore";
		final String ECrootPKpath = "C://CommunicationTest/CA/ECrootPrivateKey.key";
		final String RSArootPKpath = "C://CommunicationTest/CA/RSArootPrivateKey.key";
		final char[] password_KeyStore = "root".toCharArray();
		final char[] password_RootKey = "rootKey".toCharArray();
		//String keyInstance = "EC";

		File keystorefile = new File("C:/CommunicationTest/CA/rootKeystore");
		Path keystorePath = Paths.get(keystorePathString);

		


		if (Files.exists(keystorePath)){
			System.out.println("--> Keystore already exists");
			//String aliasEC2 = "temp"; 
        	rootPrivateKeyEC = KeysAndCertificates_short.getKeyFromKeystore(keystorefile, password_KeyStore, password_RootKey, aliasEC);
        	rootCertificateEC = KeysAndCertificates_short.getCertificatefromKeystore(keystorefile, password_KeyStore, aliasEC);
        	//String rootCertificateECString = Base64.encode(rootCertificateEC.getEncoded());
        	//System.out.println("EC = " + rootCertificateECString);
        	rootPrivateKeyRSA = KeysAndCertificates_short.getKeyFromKeystore(keystorefile, password_KeyStore, password_RootKey, aliasRSA);
        	rootCertificateRSA = KeysAndCertificates_short.getCertificatefromKeystore(keystorefile, password_KeyStore, aliasRSA);
        	//String rootCertificateRSAString = Base64.encode(rootCertificateRSA.getEncoded());
        	//System.out.println("RSA = " + rootCertificateRSAString);
//        	System.out.println("+++");
//        	System.out.println(rootCertificate.getSubjectDN());
        	System.out.println("--> Private key and root Certificate were loaded from keystore");
//        	System.out.println(rootPrivateKey);
//        	System.out.println(rootCertificate);
			
		}
		
		else if (Files.notExists(keystorePath)){
			
			/*
			 * create KeyStore
			 */
			
			KeysAndCertificates_short.createKeystore(keystorefile, password_KeyStore);
			System.out.println("--> Keystore was created");
			
			// create selfsigned Certificate for Trusted Center(CA), based on
			// generated EC caKeyPair
			String algorithmEC = "SHA1withECDSA";
			long longvalue2 = 1234567890;
			int rootCurve = 256;
			KeyPair rootKeyPairEC = KeysAndCertificates_short.generateECKeypair(rootCurve, longvalue2);
			System.out.println("--> EC Keypair was generated");
			String dnRoot = "CN=IHP_CA, OU=CY, O=IHP, L=FFO, ST=Brandenburg, C=DE";
			rootCertificateEC = KeysAndCertificates_short.generateCertificate(dnRoot, rootKeyPairEC, 365, algorithmEC);
			System.out.println("--> EC root Certificate was generated");
			rootPrivateKeyEC = rootKeyPairEC.getPrivate();
			KeysAndCertificates_short.putKeyAndCertToKeystore(keystorefile, password_KeyStore, aliasEC, rootPrivateKeyEC, password_RootKey, KeysAndCertificates_short.certificateChain(rootCertificateEC, rootCertificateEC));
			System.out.println("--> EC Certificate and Private key are available in the keystore");
			// Save EC CA Private key to file
			FileOutputStream fos = new FileOutputStream(ECrootPKpath);
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rootPrivateKeyEC.getEncoded());
			fos.write(pkcs8EncodedKeySpec.getEncoded());
			fos.close();
			
			// create selfsigned Certificate for Trusted Center(CA), based on
			// generated RSA caKeyPair
			KeyPairGenerator rsakpg = KeyPairGenerator.getInstance("RSA");
			rsakpg.initialize(2048);
			KeyPair rootKeyPairRSA = rsakpg.genKeyPair();
			System.out.println("--> RSA Keypair was generated");
			String algorithmRSA = "SHA1withRSA";
			rootCertificateRSA = KeysAndCertificates_short.generateCertificate(dnRoot, rootKeyPairRSA, 365, algorithmRSA);
			System.out.println("--> RSA root Certificate was generated");
			rootPrivateKeyRSA = rootKeyPairRSA.getPrivate();
			KeysAndCertificates_short.putKeyAndCertToKeystore(keystorefile, password_KeyStore, aliasRSA, rootPrivateKeyRSA, password_RootKey, KeysAndCertificates_short.certificateChain(rootCertificateRSA, rootCertificateRSA));
			System.out.println("--> RSA Certificate and Private key are available in the keystore");
			// Save RSA CA Private key to file
			fos = new FileOutputStream(RSArootPKpath);
			pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rootPrivateKeyRSA.getEncoded());
			fos.write(pkcs8EncodedKeySpec.getEncoded());
			fos.close();
		}
		
		
		Server.Server2.main(args);
		
	}
}
