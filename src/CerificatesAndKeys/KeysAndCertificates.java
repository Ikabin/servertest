package CerificatesAndKeys;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Iterator;
import java.util.Set;

//import javax.security.auth.x500.X500Principal;



//import sun.security.tools.KeyTool;

public class KeysAndCertificates {

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
	 * Put Private Key to keystore
	 */
	public static void putKeyToKeystore(File keystore, char[] password_KeyStore, String alias, PrivateKey privateKey, char[] password_PrivateKey, Certificate[] chain) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException{
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
	 * Put Certificate from file to keyStore
	 */
	public static void putCertToKeystore(File keystore, char[] password, String alias, String certificatepath) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
	    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		//to access keystore it must be loaded at first
        FileInputStream fis = new FileInputStream(keystore);
        ks.load(fis, password);
        
        FileInputStream certstream = new FileInputStream(certificatepath);///
        BufferedInputStream bis = new BufferedInputStream(certstream);///
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate certs = null; 
        while (bis.available() > 0){
        	certs = cf.generateCertificate(bis);
        	ks.setCertificateEntry(alias, certs);
        }
        //add certificate
        ks.setCertificateEntry(alias, certs);
        //save keystore
        FileOutputStream out = new FileOutputStream(keystore);
        ks.store(out, password);
        out.close();
	}
	

	
	/*
	 * Put generated certificate to keystore
	 */
	public static void putOwnCertToKeystore(File keystore, char[] password, String alias, X509Certificate cert) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
	    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		
	    //to access keystore it must be loaded at first
        FileInputStream fis = new FileInputStream(keystore);
        ks.load(fis, password);
        ks.setCertificateEntry(alias, cert);
        
        //save keystore
        FileOutputStream out = new FileOutputStream(keystore);
        ks.store(out, password);
        out.close();
	}
	
	
	
	
	
	
	/*
	 * Generate keypair
	 */
	public static KeyPair generateKeypair(int nistcurve, long longvalue) throws Exception{
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
//		PrivateKey privkey;
//		PublicKey pubkey;
		kpg = KeyPairGenerator.getInstance("EC");
		
//		System.out.println("----------------KEYS, GENERATED WITH 'RANDOM' PARAMETER (PRNG)----------------");//
//		System.out.println();//	

		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(longvalue);
				 
		kpg.initialize(params, random);//
	//	System.out.println("random (format:" + random.getAlgorithm() + ") = " + random);
	//	System.out.println();//
		keypair = kpg.generateKeyPair();
	//	privkey = keypair.getPrivate();
		
	//	byte[] privkeybytes1 = privkey.getEncoded();
	//	System.out.println("PRIVATE KEY1 = " + Base64.encode(privkeybytes1));
	//	pubkey = keypair.getPublic();
	//	System.out.println("PUBLIC KEY1 = " + pubkey);
	//	System.out.println();//
		
		return keypair;
	}
	
	 
	/*
	 * Create self-signed certificate
	 */
	
		
	
	
	
	
	
	
	public static Certificate[] certificateChain(X509Certificate signedCertificate, X509Certificate certificateCA){
		Certificate[] chain = new Certificate[2];
		chain[0] = signedCertificate;
		chain[1] = certificateCA;
		return chain;
	}
	
	
	
	
	/*
	 * Show Certificate
	 */
	public static void showCertificate(File keystore, char[] password, String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException{
		FileInputStream fin = new FileInputStream(keystore);
	    KeyStore kstore = KeyStore.getInstance(KeyStore.getDefaultType());
		kstore.load(fin, password);
		Certificate cert = kstore.getCertificate(alias);
		System.out.println(cert);
		System.out.println(cert.getType());
	}
	
	
	/*
	 * Export Certificate to cert.File from keystore
	 */
	public static void exportCertificate(File keystore, char[] password, String alias, File certificateoutpath) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, Exception{
		FileInputStream fin = new FileInputStream(keystore);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(fin, password);
		Certificate cert = ks.getCertificate(alias);
		byte buf[] = cert.getEncoded();
		FileOutputStream os = new FileOutputStream(certificateoutpath);
		os.write(buf);
		os.close();
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
	
	
	
	/*
	 * Export Certificate to cert.File
	 */
	public static void exportCert(X509Certificate cert, File certificateoutpath) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, Exception{
		byte buf[] = cert.getEncoded();
		FileOutputStream os = new FileOutputStream(certificateoutpath);
		os.write(buf);
		os.close();
	}
	
	
	/*
	 * ecport certificate chain
	 */
	public static void exportChain(X509Certificate[] cert, File certificateoutpath) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, Exception{
		byte buf[] = cert[0].getEncoded();
		byte buf1[] = cert[1].getEncoded();
		FileOutputStream os = new FileOutputStream(certificateoutpath);
		os.write(buf);
		os.write(buf1);
		os.close();
	}
		
	
	/*
	 * create request to sign certificate
	 */
	
	
	
	/*
	 * CRL
	 */
	public static void certRevList(String[] args) throws CRLException, CertificateException, IOException{
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		FileInputStream in = new FileInputStream(args[0]);
		X509CRL crl =  (X509CRL) cf.generateCRL(in);
		Set<? extends X509CRLEntry> s = crl.getRevokedCertificates();//?
		if (s != null && s.isEmpty() == false){
			Iterator<? extends X509CRLEntry> t = s.iterator();//?
			while (t.hasNext()) {
				X509CRLEntry entry = (X509CRLEntry) t.next();
				System.out.println("Serial number = " + entry.getSerialNumber().toString(16));
				System.out.println("Revocation date = " + entry.getRevocationDate());
				System.out.println("Extensions = " + entry.hasExtensions());
			}
		}
		in.close();
		
	}
 
	/*
	 * Sign the message
	 */
    public static byte[] signTheMessage (String message, PrivateKey privatekey, X509Certificate certificate) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException{
    	//	byte[] messagebytes = message.getBytes(Charset.forName("UTF-8"));
    		byte[] messagebytes = message.getBytes("UTF-8");
	        Signature signature = Signature.getInstance(certificate.getSigAlgName());
//			System.out.println("Message signed using *** " + certificate.getSigAlgName() + " *** algorithm");
	        
			//signing with private key
	        signature.initSign(privatekey);
	        signature.update(messagebytes); 
	        byte[] signaturebytes = signature.sign();
	    	int length1 = signaturebytes[3];
	    	int length2 = signaturebytes[3 + length1 + 2];
	        while (length1 < 30 || length2 < 30){
	        	signaturebytes = signature.sign();
		    	length1 = signaturebytes[3];
		    	length2 = signaturebytes[3 + length1 + 2];
	        }
	    	return   signaturebytes;
    }    
	
	/*
	 * Signature verifying
	 */
	public static boolean signatureVerification(String message, X509Certificate certificate, byte[] signaturebytes) throws SignatureException, InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException{
		
		//verifying with public key
        Signature signature = Signature.getInstance(certificate.getSigAlgName());
        signature.initVerify(certificate.getPublicKey());
        signature.update(message.getBytes("UTF-8"));
        return signature.verify(signaturebytes);   
	}
	
	/*
	 * Certificate checking for validity, signature
	 */
	public static void checkCertificate(X509Certificate usercertificate, X509Certificate cacertificate){
//			String certsignaturebytes = new BASE64Encoder().encode(usercertificate.getSignature()); //signature of customer's certificate
//	        System.out.println("Cerificate Verification: true");
//	        System.out.println("Signature of Customer's Certificate: " + certsignaturebytes);
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
		
	
	/*
 *Function to modify signature for C# 
 */

public static byte[] signatureConversion(byte[] signaturebytes, int ecurve){
	
	int signaturesize = 0;
    switch(ecurve){
    case 256:
    	signaturesize = 64;
    	break;
/*
    case 384:
    	signaturesize = 96;
    	break;
*/  
    }
            
    int i = 0;
    int j = 0;
    int i2;
    byte[] signatureModified = new byte[signaturesize];
	int length1 = signaturebytes[3];
	int length2 = signaturebytes[5 + length1];
	
	//first part of signature
    switch(length1){
    case 30:
			signatureModified[j] = 0;
			j++;
			signatureModified[j] = 0;
			j++;
			for (i = 4; i < 4 + length1; i++){
				signatureModified[j] = signaturebytes[i];
				j++;
			}
	break;    
    case 31:
    		signatureModified[j] = 0;
    		j++;
    		for (i = 4; i < 4 + length1; i++){
    			signatureModified[j] = signaturebytes[i];
    			j++;
    		}
    	break;
    case 32:
    		for (i = 4; i < 4 + length1; i++){
    			signatureModified[j] = signaturebytes[i];
    			j++;
    		}
    	break;
    case 33:
    		for (i = 5; i < 4 + length1; i++){
    			signatureModified[j] = signaturebytes[i];
    			j++;
    		}
    	break;
    }
    i2 = i + 2;
    
    //second part of signature
    switch(length2){
    case 30:
			signatureModified[j] = 0;
			j++;
			signatureModified[j] = 0;
			j++;
		  	for (i = i + 2; i < i2  + length2; i++){
		  		signatureModified[j] = signaturebytes[i];
		  		j++;
		}
	break;
    case 31:
    		signatureModified[j] = 0;
    		j++;
   		  	for (i = i + 2; i < i2  + length2; i++){
   		  		signatureModified[j] = signaturebytes[i];
   		  		j++;
    		}
    	break;
    case 32:
    		for (i = i + 2; i < i2 + length2; i++){
    			signatureModified[j] = signaturebytes[i];
    			j++;
    		}
    	break;
    case 33:
    		for (i = i + 3; i < i2 + length2; i++){
    			signatureModified[j] = signaturebytes[i];
    			j++;
    		}
    	break;
    }
    
    return signatureModified;
}
	
	
	/*
	 * Signature for C#
	 */
	public static byte[] signatureC(byte[] signaturebytes, int ecurve){

		byte[] signatureForC = null;
        switch(ecurve){
        case 256:
        	signatureForC = signatureConversion(signaturebytes, ecurve);
        	break;
        case 384:
        	signatureForC = signatureConversion(signaturebytes, ecurve);	
        	break;
        }
        return signatureForC;
	}

	
	public static void createPKCS12KeyStore(String keyStorePwd, String keyStoreFile,
		    PrivateKey privateKey, X509Certificate certificate)
		    throws Exception {

		    char[] pwd = keyStorePwd.toCharArray();

		    KeyStore ks = KeyStore.getInstance("PKCS12");
		    ks.load(null, pwd);

		    KeyStore.ProtectionParameter protParam =
		        new KeyStore.PasswordProtection(pwd);
		    Certificate[] certChain =    new Certificate[] { certificate };
		    KeyStore.PrivateKeyEntry pkEntry =
		        new KeyStore.PrivateKeyEntry(privateKey, certChain);
		    ks.setEntry("keypair", pkEntry, protParam);

		    FileOutputStream fos = new FileOutputStream(keyStoreFile);
		    ks.store(fos, pwd);
		    fos.close();
		}

	
	public static PrivateKey loadPrivateKeyFromFile(String keyPath, String keyInstance) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		File filePrivateKey = new File(keyPath);
		FileInputStream fis = new FileInputStream(keyPath);
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();
		KeyFactory keyFactory = KeyFactory.getInstance(keyInstance);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		return privateKey;
	}



	    public static KeyPair getPrivateKey(KeyStore keystore, String alias, char[] password) {
	        try {
	            // Get private key
	            Key key = keystore.getKey(alias, password);
	            if (key instanceof PrivateKey) {
	                // Get certificate of public key
	                java.security.cert.Certificate cert = keystore.getCertificate(alias);

	                // Get public key
	                PublicKey publicKey = cert.getPublicKey();

	                // Return a key pair
	                return new KeyPair(publicKey, (PrivateKey) key);
	            }
	        } catch (UnrecoverableKeyException e) {
	        } catch (NoSuchAlgorithmException e) {
	        } catch (KeyStoreException e) {
	        }
	        return null;
	    }
	    

}
	
	