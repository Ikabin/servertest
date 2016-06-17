package CerificatesAndKeys;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Date;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;




public class KeysAndCertificates_short {

	/*
	 * Create keystore
	 */
	public static void createKeystore(File keystore, char[] password) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		
		//create keystore 
	    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	    ks.load(null, password);
	    
	    //save keystore
	    FileOutputStream fos = new FileOutputStream(keystore);
	    ks.store(fos, password);
        fos.close();
	}



	/*
	 * Generate keypair
	 */
	public static KeyPair generateECKeypair(int nistcurve, long longvalue) throws Exception{
		BigInteger p , a, b, x, y, n;
		int h;
		
			//curve secp192r1
			p = new BigInteger("6277101735386680763835789423207666416083908700390324961279");	//prime, module
			a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", 16);			//ec coefficient
			b = new BigInteger("2455155546008943817740293915197451784769108058161191238065");	//ec coefficient	
			x = new BigInteger("602046282375688656758213480587526111916698976636884684818"); 
			y = new BigInteger("174050332293622031404857552280219410364023488927386650641");
			n = new BigInteger("6277101735386680763835789423176059013767194773182842284081");	//order of the base point
			h = 1;																				//cofactor
		
			switch(nistcurve){
			case 256:	//curve secp256r1
				p = new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951");	//prime, module//perepisivaetsa kak est
				a = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);				//ec coefficient//perepisivaetsa kak est
				b = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);				//ec coefficient	
				x = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16); 			//perepisivaetsa kak est
				y = new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16); 			//perepisivaetsa kak est
				n = new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369");	//order of the base point //perepisivaetsa kak est
				h = 1;																									//cofactor
				break;
			case 384:
				//curve secp384r1
				p = new BigInteger("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319");	//prime, module
				a = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16);					//ec coefficient
				b = new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16);					//ec coefficient	
				x = new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760aB7", 16); 
				y = new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5F", 16);
				n = new BigInteger("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643");	//order of the base point
				h = 1;		//cofactor
				break;
			case 521:
				//curve secp521r1
				p = new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");	//prime, module
				a = new BigInteger("000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16);						//ec coefficient
				b = new BigInteger("00000051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16);						//ec coefficient	
				x = new BigInteger("000000c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16); 
				y = new BigInteger("0000011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16);
				n = new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449");	//order of the base point
				h = 1;		//cofactor
				break;
			}
			
			
		ECField field = new ECFieldFp(p);	
		EllipticCurve curve = new EllipticCurve(field, a, b);
		ECPoint g = new ECPoint(x, y);		//base point
		
		
		ECParameterSpec params = new ECParameterSpec(curve, g, n, h);
		System.out.println();
		KeyPairGenerator kpg;		 
		KeyPair keypair; 

		kpg = KeyPairGenerator.getInstance("EC");

		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(longvalue);
				 
		kpg.initialize(params, random);
		keypair = kpg.generateKeyPair();
		
		return keypair;
	}





	/*
	 * Create self-signed certificate
	 */
	




	/*
	 * Create cert chain
	 */
	public static Certificate[] certificateChain(X509Certificate signedCertificate, X509Certificate certificateCA){
		Certificate[] chain = new Certificate[2];
		chain[0] = signedCertificate;
		chain[1] = certificateCA;
		return chain;
	}
	

	/*
	 * Put Private Key and cert chain to keystore
	 */
	public static void putKeyAndCertToKeystore(File keystore, char[] password_KeyStore, String alias, PrivateKey privateKey, char[] password_PrivateKey, Certificate[] chain) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException{
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		//to access keystore it must be loaded at first
        FileInputStream fis = new FileInputStream(keystore);
        ks.load(fis, password_KeyStore);
        //save the key to keystore
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password_PrivateKey);
        KeyStore.PrivateKeyEntry pkEntry = new KeyStore.PrivateKeyEntry(privateKey, chain);
        ks.setEntry(alias, pkEntry, protParam);
        //save keystore
        FileOutputStream out = new FileOutputStream(keystore);
        ks.store(out, password_KeyStore);
        out.close();
               
	}
	
	/*
	 * Get Private Key from KeyStore
	 */
	public static PrivateKey getKeyFromKeystore(File keystore, char[] password_KeyStore, char[] password_PrivateKey, String alias) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableEntryException{
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		//to access keystore it must be loaded at first
	    FileInputStream fis = new FileInputStream(keystore);
	    ks.load(fis, password_KeyStore);
	    //retrieve the Private Key    
	    KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password_PrivateKey);
	    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)ks.getEntry(alias, protParam);
	    PrivateKey myLoadedPrivateKey = pkEntry.getPrivateKey();
        //save keystore
	    FileOutputStream out = new FileOutputStream(keystore);
	    ks.store(out, password_KeyStore);
	    out.close();
	    return myLoadedPrivateKey;
	    
	}


	/*
	 * Get the certificate from keystore
	 */
	public static X509Certificate getCertificatefromKeystore(File keystore, char[] password, String alias) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, Exception{
		FileInputStream fin = new FileInputStream(keystore);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(fin, password);
		Certificate cert = ks.getCertificate(alias);
		return (X509Certificate) cert;
	}
	

////////////////////////////////////

	
	/*
	 * Certificate checking for validity, signature
	 */
	public static void checkCertificate(X509Certificate usercertificate, X509Certificate cacertificate){
          try {
			usercertificate.checkValidity();
		} catch (CertificateExpiredException e) {
			// TODO Auto-generated catch block
			System.out.println("***   User's Certificate has expired!   ***");
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			// TODO Auto-generated catch block
			System.out.println("***   User's Certificate isn't valid yet!   ***");
			e.printStackTrace();
		}
          try {
			cacertificate.checkValidity();
		} catch (CertificateExpiredException e) {
			// TODO Auto-generated catch block
			System.out.println("***   CA Certificate has expired!   ***");
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			// TODO Auto-generated catch block
			System.out.println("***   CA Certificate expired!   ***");
			e.printStackTrace();
		}
          try {
			usercertificate.verify(cacertificate.getPublicKey());
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			System.out.println("***   Signature doesn't match!   ***");
	//		e.printStackTrace();
		}
	}
		


	    
		 public static X509Certificate certificateFromText(String certString) throws CertificateException, IOException{
			 Decoder decoder = Base64.getDecoder();
			 byte[] certBytes = decoder.decode(certString);
			
	         CertificateFactory cf = CertificateFactory.getInstance("X.509");
	         InputStream in = new ByteArrayInputStream(certBytes);
	         X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
	         in.close();
			 return cert;
		 }
		 
		 //request to sign self-signed certificate
		 public static String signRequest(String certificate, String password){
				String signedCert = "";
				int serverPort = 6666; 
		        String address = "172.16.43.134";
			    Socket socket;
		        try {
		            InetAddress ipAddress = InetAddress.getByName(address); 
		            socket = new Socket(ipAddress, serverPort);
		           
		            InputStream sin = socket.getInputStream();
		            OutputStream sout = socket.getOutputStream();

		            DataInputStream in = new DataInputStream(sin);
		            DataOutputStream out = new DataOutputStream(sout);

		            String lineIn = null;
		            String lineOut = null;
		            
	            	lineOut = ".SR>>>" + password + ">>>" + certificate;
	                out.writeUTF(lineOut); 		
	                out.flush(); 

	                
	                lineIn = in.readUTF(); 		//waiting the answer from server
	                
	                if(lineIn.startsWith("MI")){
	            		signedCert = lineIn;
	                }
		            else{
	 	                System.out.println("Cert signing procedure failed");
	 	            }
	                
	            	lineOut = ".EXIT";
	                out.writeUTF(lineOut); 		
	                out.flush(); 
	                
		            socket.shutdownInput();
		            socket.shutdownOutput();
		            socket.close();
		            
		        } catch (Exception x) {
		            x.printStackTrace();
		        }
				return signedCert;
			}
		 
		 
		 //checks if the certificate is in CA DB
		 public static boolean accessVerificationRequest(String certificate){
			 	boolean result = false;
				int serverPort = 6666; 
		        String address = "172.16.43.134";
			    Socket socket;
		        try {
		            InetAddress ipAddress = InetAddress.getByName(address); 
		            socket = new Socket(ipAddress, serverPort);
		           
		            InputStream sin = socket.getInputStream();
		            OutputStream sout = socket.getOutputStream();

		            DataInputStream in = new DataInputStream(sin);
		            DataOutputStream out = new DataOutputStream(sout);

		            String lineIn = null;
		            String lineOut = null;
		            
	            	lineOut = ".CV>>>" + certificate;
	                out.writeUTF(lineOut); 		
	                out.flush(); 

	                
	                lineIn = in.readUTF(); 		//waiting the answer from server
	                
	                if(lineIn.equals("CV_true")){
	            		result = true;
	                }
		            else{
		            	result = false;
	 	                System.out.println("Cert verification procedure failed");
	 	            }
	                
	            	lineOut = ".EXIT";
	                out.writeUTF(lineOut); 		
	                out.flush(); 
	                
		            socket.shutdownInput();
		            socket.shutdownOutput();
		            socket.close();
		            
		        } catch (Exception x) {
		            x.printStackTrace();
		        }
				return result;
			}
		 
		 
		 public static KeyPair generateRSAKeypair() throws NoSuchAlgorithmException{
			 
			 KeyPairGenerator rsakpg = KeyPairGenerator.getInstance("RSA");
			 rsakpg.initialize(2048);
			 KeyPair rsakp = rsakpg.genKeyPair();
			 return rsakp;
		 }

		 
		 
			public static X509Certificate generateCertificate(String dn,  KeyPair pair, int days, String algorithm) throws OperatorCreationException, IOException, CertificateException{
				X500Name subject = new X500Name(dn);
				PublicKey publicKey = pair.getPublic();
				Date notBefore = new Date();
				Date notAfter = new Date(notBefore.getTime() + days * 86400000);
				SecureRandom random = new SecureRandom();
				BigInteger serial = new BigInteger(64, random);
				X500Name issuer = subject;
				JcaX509v3CertificateBuilder certbuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey);
		        
				JcaContentSignerBuilder csBuilder= new JcaContentSignerBuilder(algorithm);
		        ContentSigner signer = csBuilder.build(pair.getPrivate()); 
				
		        X509CertificateHolder holder = certbuilder.build(signer); 
		        byte[] certbytes = holder.toASN1Structure().getEncoded();
		        Encoder encoder = Base64.getEncoder();
		    	String certString = encoder.encodeToString(certbytes);
		    	X509Certificate cert = certificateFromText(certString);
		        
		        

				return cert;
			}
			
			
			
			public static X509Certificate createSignedCertificate(X509Certificate certificate, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) throws OperatorCreationException, IOException, CertificateException{
				String dn_subject = "" + certificate.getSubjectDN();
				X500Name subject = new X500Name(dn_subject);
				PublicKey publicKey = certificate.getPublicKey();
				Date notBefore = certificate.getNotBefore();
				Date notAfter = certificate.getNotAfter();
				BigInteger serial = certificate.getSerialNumber();
				
				String dn_issuer = "" + issuerCertificate.getSubjectDN();
				X500Name issuer = new X500Name(dn_issuer);
				JcaX509v3CertificateBuilder certbuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey);
		        
				JcaContentSignerBuilder csBuilder= new JcaContentSignerBuilder(certificate.getSigAlgName());
		        ContentSigner signer = csBuilder.build(issuerPrivateKey); 
				
		        X509CertificateHolder holder = certbuilder.build(signer); 
		        byte[] certbytes = holder.toASN1Structure().getEncoded();
		        Encoder encoder = Base64.getEncoder();
		    	String certString = encoder.encodeToString(certbytes);
		    	X509Certificate cert = certificateFromText(certString);
		        
				return cert;
			}
}
	
	