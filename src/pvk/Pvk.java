package pvk;
/* Translated to Java by John Pritchard (jdp@syntelos.org) for the OpenSSL
 * project 2011.
 */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

import java.math.BigInteger;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

import sun.security.rsa.RSAPrivateCrtKeyImpl;


/**
 * Command line tool to create 'pvk' file for windows based code
 * signing, i.e. InstallShield.
 * 
 * Simple rewrite of Stephen N Henson's most excellent PVK in C.
 */
public class Pvk {

    public final long PVK_MAGIC =  0xb0b5f11eL;
    public final int PVK_SALTLEN = 0x10;
    public final int PVK_NONE =    0x0;
    public final int PVK_WEAK =    0x1;
    public final int PVK_STRONG =  0x2;
    public final int PKEYBLOB =	   0x7;
    public final int PVK_SIG =     0x2;
    public final int PVK_KEYX =    0x1;
    public final int RSA_KEYX =    0xa400;
    public final int RSA_SIG =	   0x2400;

    private final long magic;
    private final long res;
    private final long keytype;
    private final long crypt;
    private final long saltlen;
    private final long keylen;
    private final byte[] salt;
    private final byte btype;
    private final byte version;
    private final short reserved;
    private final long keyalg;
    private final byte[] key;




    /*
     * Dump PVK structure
     */
    public Pvk(byte[] file)
    {
	super();
	int ofs = 0;
	this.magic = read_dword(file,ofs);
	if (PVK_MAGIC == this.magic){
	    ofs += 4;
	    this.res = read_dword(file,ofs);
	    ofs += 4;
	    this.keytype = read_dword(file,ofs);
	    ofs += 4;
	    this.crypt = read_dword(file,ofs);
	    ofs += 4;
	    this.saltlen = read_dword(file,ofs);
	    ofs += 4;
	    this.keylen = read_dword(file,ofs);
	    ofs += 4;
	    if (0 < this.saltlen){
		byte[] salt;
		try {
		    salt = read_bytes(file,ofs,(int)this.saltlen);
		}
		catch (ArrayIndexOutOfBoundsException exc){
		    System.err.printf("Error copying salt at offset 0x%x and length 0x%x%n",ofs,this.saltlen);
		    salt = new byte[0];
		}
		this.salt = salt;
		ofs += this.saltlen;
	    }
	    else
		this.salt = new byte[0];

	    this.btype = read_byte(file,ofs);
	    ofs += 1;
	    this.version = read_byte(file,ofs);
	    ofs += 1;
	    this.reserved = read_word(file,ofs);
	    ofs += 2;
	    this.keyalg = read_dword(file,ofs);
	    ofs += 4;
	    if (0 < this.keylen){
		int keylen = (int)(this.keylen-8);
		byte[] key;
		try {
		    key = read_bytes(file,ofs,keylen);
		}
		catch (ArrayIndexOutOfBoundsException exc){
		    System.err.printf("Error copying key at offset 0x%x and length 0x%x (exists 0x%x)%n",ofs,this.keylen,(file.length-ofs));
		    key = new byte[0];
		}
		this.key = key;
	    }
	    else
		this.key = new byte[0];
	}
	else
	    throw new IllegalArgumentException(String.format("Bad file not PVK file (MAGIC 0x%x != 0x%x)",PVK_MAGIC,this.magic));
    }
    /*
     * Convert RSA key into PVK structure
     */
    public Pvk(RSAPrivateCrtKeyImpl rsa)
    {
	super();

	this.magic = PVK_MAGIC;
	this.res = 0;
	this.crypt = 0;
	this.saltlen = 0;
	this.btype = PKEYBLOB;
	this.version = 2;

	this.salt = null;

        this.keyalg = RSA_SIG;
	this.keytype = PVK_SIG;
	this.reserved = 0;

	/* Prepare PVK key blob 
	 */
	final int numbytes = (rsa.getModulus().bitLength()>>3);
	final int numbytesD2 = (numbytes>>1);

	this.key = new byte[(12 + numbytes * 5)];

	int ofs = 0;

	this.key[ofs++] = 'R';
	this.key[ofs++] = 'S';
	this.key[ofs++] = 'A';
	this.key[ofs++] = '2';

	put_dword(this.key, ofs, (numbytes << 3));
	ofs += 4;
	put_dword(this.key, ofs, rsa.getPublicExponent().longValue());  //RSA_E
	ofs += 4;
	put_bytes(this.key, ofs, rsa.getModulus());                     //RSA_N
	ofs += numbytes;
	put_bytes(this.key, ofs, rsa.getPrimeP());                      //RSA_P
	ofs += numbytesD2;
	put_bytes(this.key, ofs, rsa.getPrimeQ());                      //RSA_Q
	ofs += numbytesD2;
	put_bytes(this.key, ofs, rsa.getPrimeExponentP());              //RSA_DMP1
	ofs += numbytesD2;
	put_bytes(this.key, ofs, rsa.getPrimeExponentQ());              //RSA_DMQ1
	ofs += numbytesD2;
	put_bytes(this.key, ofs, rsa.getCrtCoefficient());              //RSA_IQMP
	ofs += numbytesD2;
	put_bytes(this.key, ofs, rsa.getPrivateExponent());             //RSA_D
	ofs += numbytes;
	this.keylen = (ofs+8);
    }

    public void write(OutputStream out)
	throws IOException
    {
	write_dword(out, this.magic);
	write_dword(out, this.res);
	write_dword(out, this.keytype);
	write_dword(out, this.crypt);
	write_dword(out, this.saltlen);
	write_dword(out, this.keylen);
	if (0 < this.saltlen) 
	    out.write(this.salt, 0, (int)this.saltlen);

	out.write(this.btype);
	out.write(this.version);
	write_word(out, this.reserved);
	write_dword(out, this.keyalg);

	if (this.keylen > 0) {

	    int keylen = (int)(this.keylen-8);

	    out.write(this.key, 0, keylen);
	}
    }
    public void dump(PrintStream out){
	out.printf("MAGIC 0x%x%n",this.magic);
	out.printf("RES 0x%x%n",this.res);
	out.printf("KEYTYPE 0x%x%n",this.keytype);
	out.printf("CRYPT 0x%x%n",this.crypt);
	out.printf("SALTLEN 0x%x%n",this.saltlen);
	out.printf("KEYLEN 0x%x%n",this.keylen);
	out.printf("SALT %s%n",PrintHex(this.salt));
	out.printf("BTYPE 0x%x%n",this.btype);
	out.printf("VERSION 0x%x%n",this.version);
	out.printf("RESERVED 0x%x%n",this.reserved);
	out.printf("KEYALG 0x%x%n",this.keyalg);
	out.printf("KEY %s%n",PrintHex(this.key));
    }


    private static void write_word(OutputStream out, int dat)
	throws IOException
    {
	out.write(dat & 0xff);
	out.write((dat >> 8) & 0xff);
    }
    private static void write_dword(OutputStream out, long dat)
	throws IOException
    {
	out.write( (int)(dat & 0xff));
	out.write( (int)((dat >> 8) & 0xff));
	out.write( (int)((dat >> 16) & 0xff));
	out.write( (int)((dat >> 24) & 0xff));
    }
    private static void put_dword(byte[] p, int ofs, long dat)
    {
	p[ofs+0] = (byte)(dat & 0xff);
	p[ofs+1] = (byte)((dat >> 8) & 0xff);
	p[ofs+2] = (byte)((dat >> 16) & 0xff);
	p[ofs+3] = (byte)((dat >> 24) & 0xff);
    }
    /* Convert bignum to little endian format
     */ 
    private static void put_bytes(byte[] p, int ofs, BigInteger num)
    {
	final byte[] bytes = TrimBN(num.toByteArray());
	final int nbyte = bytes.length;
	final int nbyteD2 = (nbyte>>1);
	final int nbyteM1 = (nbyte-1);
	/*
	 *  Copy
	 */
	System.arraycopy(bytes,0,p,ofs,nbyte);
	/* 
	 *  Reverse byte order
	 */
	byte c;
	for (int i = 0, s, t; i < nbyteD2; i++) {
	    s = (ofs + i);
	    t = (ofs + nbyteM1 - i);
	    c = p[s];
	    p[s] = p[t];
	    p[t] = c;
	}
    }
    private static byte read_byte(byte[] file, int ofs){

	return (file[ofs]);
    }
    private static short read_word(byte[] file, int ofs){
	int a = (file[ofs++] & 0xFF);
	int b = (file[ofs] & 0xFF);
	return (short)((b<<8)|a);
    }
    private static long read_dword(byte[] file, int ofs){
	long a = (file[ofs++] & 0xFF);
	long b = (file[ofs++] & 0xFF);
	long c = (file[ofs++] & 0xFF);
	long d = (file[ofs] & 0xFF);
	return (a|(b<<8)|(c<<16)|(d<<24));
    }
    private static byte[] read_bytes(byte[] file, int ofs, int len){
	byte[] copy = new byte[len];
	System.arraycopy(file,ofs,copy,0,len);
	return copy;
    }
    private final static char[] Hex = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    private static String PrintHex(byte[] bits){
	StringBuilder string = new StringBuilder();
	for (int cc = 0; cc < bits.length; cc++){
	    if (0 == (cc % 20)){
		string.append("\n\t");
	    }
	    else
		string.append(' ');

	    int v = (bits[cc] & 0xFF);
	    int a = ((v>>4) & 0xF);
	    int b = (v & 0xF);
	    string.append(Hex[a]);
	    string.append(Hex[b]);
	}
	return string.toString();
    }
    private static byte[] TrimBN(byte[] bn){
	if (0 == bn[0]){
	    final int nlen = (bn.length-1);
	    byte[] copy = new byte[nlen];
	    System.arraycopy(bn,1,copy,0,nlen);
	    return copy;
	}
	else
	    return bn;
    }
    private static byte[] ReadBytes(File file) throws IOException {

        FileInputStream fis = new FileInputStream(file);
        try {
            DataInputStream dis = new DataInputStream(fis);
            byte[] bytes = new byte[(int)file.length()];
            dis.readFully(bytes);
            return bytes;
        }
        finally {
            fis.close();
        }
    }
    static void usage(){
        System.err.println("Usage");
        System.err.println();
        System.err.println("  Pvk  file.pvk");
        System.err.println();
        System.err.println("Description");
        System.err.println();
        System.err.println("  Read input file 'file.pvk' to output");
        System.err.println("  content for checking and debugging the");
        System.err.println("  file format.");
        System.err.println();
        System.err.println("Usage");
        System.err.println();
        System.err.println("  Pvk  prikey.pk8.der prikey.pvk");
        System.err.println();
        System.err.println("Description");
        System.err.println();
        System.err.println("  Read input file 'prikey.der' to produce output");
        System.err.println("  file 'prikey.pvk'.");
        System.err.println();
        System.exit(1);
    }
    private final static KeyFactory RSA;
    static {
        try {
            RSA = KeyFactory.getInstance("RSA");
        }
        catch (Exception exc){
            exc.printStackTrace();
            throw new InternalError();
        }
    }
    public static void main(String[] argv){
        try {
            File derf, pvkf;

            switch (argv.length){
	    case 1:
		derf = null;
		pvkf = new File(argv[0]);
		break;
            case 2:
                derf = new File(argv[0]);
                pvkf = new File(argv[1]);
                break;
            default:
                usage();
                return;
            }
	    if (null == derf){

		Pvk pvk = new Pvk(ReadBytes(pvkf));
		pvk.dump(System.out);
                System.exit(0);
	    }
            else if (!derf.isFile()){
                usage();
                return;
            }
	    else {
		PKCS8EncodedKeySpec keypri = new PKCS8EncodedKeySpec(ReadBytes(derf));

                RSAPrivateCrtKeyImpl rsa = (RSAPrivateCrtKeyImpl)RSA.generatePrivate(keypri);

                System.err.printf("Read Private Key '%s %s' from %s%n",keypri.getFormat(),rsa.getAlgorithm(),derf.getPath());

                OutputStream out = new FileOutputStream (pvkf);
                try {
		    Pvk pvk = new Pvk(rsa);
		    pvk.write(out);
                }
                finally {
                    out.flush();
                    out.close();
                    out = null;
                }
                System.err.printf("Wrote PVK to %s%n",pvkf.getPath());
                System.exit(0);
            }
        }
        catch (Exception exc){

            exc.printStackTrace();
            System.exit(1);
        }
    }
}

