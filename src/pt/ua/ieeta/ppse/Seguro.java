/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package pt.ua.ieeta.ppse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Rosa Saraiva
 */
public class Seguro
{
    public static KeyPair generateKeyPair(int numBits, String seed) throws NoSuchAlgorithmException
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(seed.getBytes());
        keyGen.initialize(numBits,random);
        KeyPair keyPair = keyGen.genKeyPair();

        return keyPair;
    }

    public static Key generateSymetricKey(int numBits, String seed, String alg) throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance(alg);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(seed.getBytes());
        keyGen.init(numBits, random);

        return keyGen.generateKey();
//        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
//        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//
//        KeySpec spec = new PBEKeySpec(seed.toCharArray(), SecureRandom.getSeed(8), 1024, 128);
//        SecretKey tmp = factory.generateSecret(spec);
//        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
//
//        return secret;
    }

    



    public static String encrypt(String message, Key key, String alg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException 
    {
        String encryped = null;
        if(key != null)
        {

            Cipher cipher = Cipher.getInstance(alg);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] enc = cipher.doFinal(message.getBytes());


            encryped = toHex(enc);//new String(enc);
        }
        return encryped;
    }

    public static String decrypt(String encrypted, Key key, String alg) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException 
    {
        String message = null;
        if(key != null)
        {

            Cipher cipher = Cipher.getInstance(alg);
            cipher.init(Cipher.DECRYPT_MODE, key);
            //byte[] msg = cipher.doFinal(encrypted.getBytes());
            byte[] msg = cipher.doFinal(toByte(encrypted));
            message = new String(msg);
        }
        return message;
    }

    public static void encrypt(File file, File encrypted, Key key,String alg) throws Exception
    {        
        if(key != null)
        {
            long length = file.length();
            if (length > Integer.MAX_VALUE)
            {
                throw new IOException("File too big: "+file.getName());
            }
            byte[] content = new byte[(int)length];

            InputStream in = new FileInputStream(file);

            int offset = 0;
            int numRead = 0;

            while (offset < content.length && (numRead=in.read(content, offset, content.length-offset)) >= 0)
            {
                offset += numRead;
            }
             // Ensure all the bytes have been read in
            if (offset < content.length)
            {
                throw new IOException("Could not completely read file "+file.getName());
            }

            Cipher cipher = Cipher.getInstance(alg);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            byte[] enc = cipher.doFinal(content);

            in.close();

            OutputStream out = new FileOutputStream(encrypted);
            out.write(enc);
            out.close();
        }
    }

    public static void decrypt(File encrypted, File file, Key key) throws Exception
    {
        if(key != null)
        {
            long length = encrypted.length();
            if (length > Integer.MAX_VALUE)
            {
                throw new IOException("File too big: "+encrypted.getName());
            }
            byte[] enc = new byte[(int)length];

            InputStream in = new FileInputStream(encrypted);

            int offset = 0;
            int numRead = 0;

            while (offset < enc.length && (numRead=in.read(enc, offset, enc.length-offset)) >= 0)
            {
                offset += numRead;
            }

            if (offset < enc.length)
            {
                throw new IOException("Could not completely read file "+encrypted.getName());
            }


            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);


            byte[] content = cipher.doFinal(enc);

            in.close();

            OutputStream out = new FileOutputStream(file);
            out.write(content);
            out.close();
        }
    }

    public static String toHex (byte buf[])
    {
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++)
        {
            if (((int) buf[i] & 0xff) < 0x10)
            strbuf.append("0");

            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }

        return strbuf.toString();
     }

    private static byte[] toByte (String hex)
    {

        byte[] bts = new byte[hex.length() / 2];
        for (int i = 0; i < bts.length; i++)
        {
            bts[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }

        return bts;
    }




}
