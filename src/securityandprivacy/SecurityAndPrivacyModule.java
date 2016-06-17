/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securityandprivacy;

import java.util.HashMap;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

/**
 *
 * @author e-balance
 */
public class SecurityAndPrivacyModule {
	//
	// the storage and parameters
	//
    int numberSize = 64;	//size of generated numbers in bits
    long modulus = 2^numberSize;

    //
    //the security storage - privacy homomorphism
    //
    private HashMap<String, PRNGSet> PRNGSets = null;
    private HashMap<String, HashMap<String, PRNGInit>> PRNGInits = null;
    
    //
    //the security storage - public key crypto
    //
    private Certificate cert;
    private KeyPair keypair;
    private Signature signature;

    
    //
    // Constructor
    //
    public SecurityAndPrivacyModule(int size, Certificate incert, KeyPair inkeypair){
    	numberSize = size;
    	cert = incert;
    	keypair = inkeypair;
		String algorithm = "";
		if(keypair.getPrivate().getAlgorithm() == "EC") algorithm = "SHA1withECDSA";
		if(keypair.getPrivate().getAlgorithm() == "RSA") algorithm = "SHA1withRSA";
		if(keypair.getPrivate().getAlgorithm() == "DSA") algorithm = "SHA1withDSA";

		try {
			signature = Signature.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			signature = null;
		} 
    	PRNGSets = new HashMap <String, PRNGSet> ();
    	PRNGInits = new HashMap <String, HashMap<String, PRNGInit>> ();
    }

    //
    // API methods
    //
    public boolean registerKeyStream(String name, long iv1, long iv2){
    	if (PRNGSets.put(name, new PRNGSet(iv1, iv2)) == null) return false;
    	PRNGInits.put(name, new HashMap<String, PRNGInit> ());
    	return true;
    }
    
    public PRNGInit getKeyStreamFork(String name, String clientName){
    	PRNGSet prngdata = PRNGSets.get(name);
    	if (prngdata == null) return null;
    	PRNGInit prnginit = new PRNGInit(prngdata.iv_1, prngdata.iv_2, prngdata.index);
    	PRNGInits.get(name).put(clientName, prnginit);
    	return prnginit;
    }
    
	public long encrypt(long plaintext, String name){
		PRNGSet prngdata = getPRNGSet(name); 
		if (prngdata == null) return 0;
		return (plaintext + getPRNGNextKey(prngdata)) % modulus;  
	}
	
	public long decrypt(long ciphertext, String name, long index){
		PRNGSet prngdata = getPRNGSet(name); 
		if (prngdata == null) return 0;
		return (ciphertext - getPRNGKey(prngdata, index)) % modulus;  
	}

	public byte[] sign(byte[] message){
		byte[] result = null;
		try {
			signature.initSign(keypair.getPrivate());
			signature.update(message);
			result = signature.sign();
		} catch (InvalidKeyException | SignatureException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			// do nothing
		}
		return result;
	}
	
	public byte[] getCertBytes(){
		byte[] result = null;
		try {
			result = cert.getEncoded();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
			// do nothing			
		}
		return result;
	}
	
	public Certificate getCert(){
		return cert;
	}
	
	
	//
	//private helper methods
	//
    private PRNGSet getPRNGSet(String name){
    	return PRNGSets.get(name);
    }
    
	private long getPRNGNextKey(PRNGSet prngdata) {
        long number = 0;
		long t1, t2;

		//System.out.println("iv1 = " + data.iv_1);
		//System.out.println("iv2 = " + data.iv_2);
		//System.out.println("idx = " + data.index);
		
		for (int i = 0; i < numberSize; i++){
			t1 = prngdata.iv_1 * (1 + prngdata.iv_1);
			t2 = prngdata.iv_2 * (1 + prngdata.iv_2);
			if (t1 > t2){
				number |= (long)1 << i;
			}
			prngdata.iv_1 = t1;
			prngdata.iv_2 = t2;
		}
		prngdata.index++;
		return number;
	}
         
	private long getPRNGKey(PRNGSet prngdata, long index) {
        long number = 0;
        long idx;
		long t1, t2;

		//System.out.println("iv1 = " + data.iv_1);
		//System.out.println("iv2 = " + data.iv_2);
		//System.out.println("idx = " + data.index);

		//if the requested index is in the past -> go back to the beginning
		if(index < prngdata.index){
			idx = 0;
			t1 = prngdata.start_iv_1;
			t2 = prngdata.start_iv_2;
		}
		else{
			idx = prngdata.index;
			t1 = prngdata.iv_1;
			t2 = prngdata.iv_2;
		}

		//catch up the index
		while(idx < index){
			for (int i = 0; i < numberSize; i++){
				t1 = prngdata.iv_1 * (1 + prngdata.iv_1);
				t2 = prngdata.iv_2 * (1 + prngdata.iv_2);
			}
			idx++;
		}

		//generate the key
		for (int i = 0; i < numberSize; i++){
			t1 = prngdata.iv_1 * (1 + prngdata.iv_1);
			t2 = prngdata.iv_2 * (1 + prngdata.iv_2);
			if (t1 > t2){
				number |= (long)1 << i;
			}
		}
		
		return number;
	}
    
    //
	//Private storage classes
	//
    private class PRNGSet{
    	public long iv_1 = 0;
    	public long iv_2 = 0;
    	public long start_iv_1 = 0;
    	public long start_iv_2 = 0;
    	public long index = 0;
    	
    	public PRNGSet(long iv1, long iv2){
    		iv_1 = iv1;
    		iv_2 = iv2;
    		start_iv_1 = iv1;
    		start_iv_2 = iv2;
    		index = 0;
    	}
    }
    
    //
	//Public storage classes
	//
    public class PRNGInit{
    	public long iv_1 = 0;
    	public long iv_2 = 0;
    	public long indexDiff = 0;
    	
    	public PRNGInit(long iv1, long iv2, long diff){
    		iv_1 = iv1;
    		iv_2 = iv2;
    		indexDiff = diff;
    	}
    }
    
}
