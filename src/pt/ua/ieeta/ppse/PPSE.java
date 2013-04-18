/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ua.ieeta.ppse;

import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.lucene.index.Term;
import org.apache.lucene.search.TermQuery;

/**
 * Posterior Playfair Searchable Encryption (PPSE)
 * 
 * Posterior Playfair Searchable Encryption (PPSE) is a method inspired by the 
 * original idea of Charles Wheatstone in which a letter replacement/shuffling 
 * is applied based on a secret text. PPSE does not apply any letter replacement
 * or shuffling at a first stage – only at a later stage does it apply a 
 * shuffling routine based on the secret key. First, the text is normalized, 
 * where punctuation is removed and the words are formed by capital letters 
 * (the metadata required to re-build the original text is also retrieved). 
 * Each individual word is then encrypted independently with the AES algorithm. 
 * The resulting ciphered text has the same number of tokens as the original.
 * Then, each individual cipher is divided into a sub-block and the text is 
 * shuffled as a whole. Finally, the encrypted metadata is concatenated to the 
 * end of the ciphered text. Note that the encrypted metadata is always longer 
 * than any sub-block. Therefore, the decryption algorithm can distinguish 
 * between data part and metadata part of the ciphered text.
 * 
 * @author Luís S. Ribeiro 
 * 
 * email: luisribeiro@ua.pt
 * 
 */
public class PPSE 
{        
    private static ArrayList<Integer> validBs = new ArrayList<>(Arrays.asList(new Integer[]{1,2,4,8,16}));
    
    private static int trapdoorMaxSize = 32;            
                 
    /**
     * Applies the PPSE cipher to the message
     * 
     * @param message message to cipher
     * @param key secret key
     * @param b number of sub-blocks per word
     * 
     * @return the equivalent ciphered message
     */
    public static String cipher(String message, Key key, int b) throws InvalidKeyException
    {  
        if(message.trim().equals(""))
            return "";
        
        int blockSize = trapdoorMaxSize / b;
        
        if(!validBs.contains(b))
        {
            throw new IllegalArgumentException("b value not valid. Choose among: 1,2,4,8 or 16.");
        }
        
        ArrayList<String> words = new ArrayList<>();
        ArrayList<String> cifras = new ArrayList<>();
        
        String metadata = getEnhancement(message);
        String metacipher = "";
        
        try 
        {
            extractWords(message, words);                                    
            metacipher = Seguro.encrypt(metadata, key, "AES");   
            
            for (Iterator<String> it = words.iterator(); it.hasNext();) 
            {
                    String word = it.next();
                    String cifra = Seguro.encrypt(word, key, "AES");                                                                            
                    String[] subCifras = splitCipher(cifra, blockSize);
                    cifras.addAll(Arrays.asList(subCifras));
            }             
        }  
        catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | FileNotFoundException ex ) 
        {
            Logger.getLogger(PPSE.class.getName()).log(Level.SEVERE, null, ex);
        }
        int intKey = keyIntoInt(key);
        shuffle(cifras, intKey);  
        
        return toMessage(cifras) + metacipher;        
    }
    
    /**
     * Rolls back the PPSE cipher into the original message
     * 
     * @param cipheredMessage ciphered message to cipher
     * @param key secret key
     * @param b number of sub-blocks per word
     * 
     * @return the original message
     */
    public static String decipher(String cipheredMessage, Key key, int b) throws InvalidKeyException, Exception
    {
        if(cipheredMessage.trim().equals(""))
            return "";
        
        ArrayList<String> words = new ArrayList<>();
        ArrayList<String> subcifras = new ArrayList<>();                           
        
        if(!validBs.contains(b))
        {
            throw new IllegalArgumentException("b value not valid. Choose among: 1,2,4,8 or 16.");
        }
        
        extractTrapdoors(cipheredMessage, subcifras);                       
        int blockSize = trapdoorMaxSize/b;        
        if(subcifras.get(0).length() != blockSize)
        {
            throw new Exception("b value is not right");
        }
        
        String metaCipher = subcifras.remove(subcifras.size()-1);                                
        int intKey = keyIntoInt(key);
        deShuffle(subcifras, intKey);                    
        
        ArrayList<String> cifras = new ArrayList<>();
        for (int i = 0; i < subcifras.size(); i+=b) 
        {                
            String cifra = "";
            for(int j = i; j < i+b; j++)
            {                    
                cifra += subcifras.get(j);
            }
            cifras.add(cifra);
        }                
        
        //Rejoin big words
        String metadata = "";
        metadata = Seguro.decrypt(metaCipher, key, "AES");                
        String bigWValue = getBTag(metadata);        
        if(bigWValue != null)
        {
                String[] bwtmp = bigWValue.split("\\*");                                  
                if(bwtmp != null)
                {                            
                    for (int i = 0; i < bwtmp.length; i++) 
                    {
                        String tuplo = bwtmp[i];
                        String[] terms = tuplo.split("@");                        
                        if(terms != null && terms.length == 2)
                        {
                            int idx = Integer.parseInt(terms[0]);
                            double len = Double.parseDouble(terms[1]);                    
                            int nWords = getnSubcifras(len);                                                                                    
                            cifras = mergeCells(cifras, idx, idx + nWords);
                        }
                    }                                                                                  
                }
        }                 
            //decipher            
            for (String cifra : cifras) 
            {
                words.add(Seguro.decrypt(cifra, key, "AES"));
            }
            String raw = toMessage(words);            
            String message = setEnhancement(raw, metadata);                        
            return message;        
    }   
    /**
     * Generates the trapdoor of the input query
     * 
     * @param query query to cipher
     * @param key secret key
     * @param b number of sub-blocks per word 
     * @param p percentage of cipher to include between [0.0,1.0]
     */
    private static String trapdoorGen(TermQuery query, Key key, int b, double p) throws InvalidKeyException
    {              
        if(!validBs.contains(b))
        {
            throw new IllegalArgumentException("b value not valid. Choose among: 1,2,4,8 or 16.");
        }
        if(p < 0.0 || p > 1.0)
        {
            throw new IllegalArgumentException("p value must be between 0.0 and 1.0.");
        }
        double x = (b*p);
        if(x != (int)x)
        {
            throw new IllegalArgumentException("b and p conjugation not valid.");
        }
        if(p == 0.0)
        {
            return "";
        }
        
        
        Term term = query.getTerm();
        String text = term.text();
        String[] words = text.split(" ");
        
        ArrayList<String> terms = new ArrayList<>();
        for(String word: words)
        {
            Term subTerm = new Term(term.field(), word);
            String enc = encryptAtomicTerm(subTerm, key, b, p);            
            terms.add("("+enc+")");
        }
        
        
        String strQuery = ""; 
        for(int i = 0; i < terms.size(); i++)
        {
            String sterm = terms.get(i);
            if(i < terms.size()-1) 
            {
                strQuery+=sterm+" OR ";
            }
            else 
            {
                strQuery+=sterm;
            }
        }
        //System.out.println(query + " -> "+strQuery);
        return strQuery;
    }       
    
    public static void main(String[] args) throws Exception 
    {
        int b = 4;
        double p = 0.25;
        Key key = Seguro.generateSymetricKey(128, "IEETAXDS-PI", "AES");      
        TermQuery term = new TermQuery(new Term("Tag","Keyword1 Keyword2 sagasg"));
        System.out.println(trapdoorGen(term, key, b, p));        
    }
    
    private static ArrayList<String> mergeCells(ArrayList<String> arr, int start, int end)
    {
        String cifra = "";
        ArrayList<String> out = new ArrayList<>();        
        if(start > 0)
        {
            out.addAll(arr.subList(0, start));        
        }
        for (int i = start; i < end; i++) 
        {
            cifra += arr.get(i);            
        }
        out.add(cifra);
        if(end < arr.size())
        {
            out.addAll(arr.subList(end, arr.size()));
        }
        
        return out;
    }
    
    
    
    private static String encryptAtomicTerm(Term term, Key key, int b, double p) throws InvalidKeyException
     {        
        String block = cipher(term.text(), key, b);
        ArrayList<String> chunks = new ArrayList<>();
        String[] subBlocks = block.split(" ");
        chunks.addAll(Arrays.asList(subBlocks));
        
        int nChunks = (int) (chunks.size() * p);
        if(nChunks < 1)
        {
            nChunks = 1;
        }
        int toRemove = chunks.size() - nChunks;
        
        Random ran = new Random(System.currentTimeMillis());
        for(int i = 0; i < toRemove; i++)
        {            
            chunks.remove(ran.nextInt(chunks.size()));
        }
        
        /*
         * Build equivalent query
         */
        String field = term.field();
        String strQuery = "";
        for(int i = 0; i < chunks.size(); i++)
        {
            String sterm = field+":"+chunks.get(i);
            if(i < chunks.size()-1) 
            {
                strQuery+=sterm+" AND ";
            }
            else 
            {
                strQuery+=sterm;
            }
        }
        
        return strQuery;
    }
    
    private static void deShuffle(ArrayList<String> arr, int key)
    {
        int size = arr.size();
        int[] exchanges = getShuffleExchanges(size, key);
        for (int i = 1; i < size; i++)
        {
            int n = exchanges[size - i - 1];
            String tmp = arr.get(i);
            arr.set(i, arr.get(n)); 
            arr.set(n,tmp);
        }        
    }
    
    private static String toMessage(ArrayList<String> list)
    {
        String message = "";
        for(String str : list)
        {            
                message += str+" ";
        }
        return message;
    }
    
    private static boolean isMajorlyUpperCase(String message) 
    {  
        int nUpper = 0;
        String tmp = message.replaceAll("\\W", "");
        for(int i = 0; i < tmp.length(); i++)
        {
            char c = tmp.charAt(i);
            if(Character.isUpperCase(c))
            {
                nUpper++;
            }
        }
        
        return nUpper > (tmp.length()-nUpper)?true:false;
    }
    
    private static String setEnhancement(String rawMessage, String metadata) throws Exception
    {
        String out = rawMessage;
        HashMap<String,String> map = new HashMap<>();
        getHashMap(metadata,map); 
        
        int sLen = Integer.parseInt(map.get("L"));
        map.remove("L");
        Character[] letters = new Character[sLen];
                
        //punctuation
        for(String key: map.keySet())
        {
            if(!Character.isAlphabetic(key.charAt(0)))
            {
                String tmp = map.get(key);
                if(tmp == null)
                    throw new Exception();
                
                String[] sIdx = tmp.split("\\*");                
                for(int i = 0; i < sIdx.length;i++)
                {
                    int idx = Integer.parseInt(sIdx[i]);
                    System.out.println(idx);
                    letters[idx] = key.charAt(0);
                }                                                                                
            }
        }        
        //fill with remaining words
        int j = 0;
        for(int i = 0; i < letters.length && j < rawMessage.length(); i++)
        {
            if(letters[i] == null)
            {
                letters[i] = rawMessage.charAt(j);
                j++;
            }
        }                
        String tmp = map.get("A");
        if(tmp == null)
            tmp = map.get("a");
        
        if(tmp == null)
            return out;
        
        boolean toUpper = map.containsKey("a")?false:true;        
        String[] capsIdx = tmp.split("\\*");
        for(int i = 0; i < capsIdx.length; i++)
        {
            if(capsIdx[i].equals(""))
                continue;
            int idx = Integer.parseInt(capsIdx[i]);
            
            if(toUpper)
            {                
                letters[idx] = Character.toUpperCase(letters[idx]);
            }
            else
            {
                letters[idx] = Character.toLowerCase(letters[idx]);
            }
        }
                                  
        out = toString(letters);        
        
        return out;
    }
    
    private static void getHashMap(String metadata, HashMap<String,String> map) throws Exception {
        String[] enhances = metadata.split(" ");        
        for(int i = 0; i < enhances.length; i++)
        {
            String[] pair = enhances[i].split("\\^");            
            if(pair.length != 2)
                continue;
            
            map.put(pair[0],pair[1]);
        } 
    }
    
    //String so tem construtores para char e não para Character 
    private static String toString(Character[] arr)
    {
        String out = "";
        for(Character c: arr)
            out+=c;
        return out;
    }
    
    
    
    private static String getEnhancement(String message)
    {
        HashMap<String,String> map = new HashMap<>();
        String caps = "A"; // text composed more by lower case        
        if(isMajorlyUpperCase(message))
        {
            caps = "a"; // text composed more by upper case
        }        
        map.put(caps, "");

        map.put("L", message.length()+"");
        
        //bigger than 15
        String[] tmp = message.split(" ");
        for (int i = 0; i < tmp.length; i++) {
            String word = tmp[i];
            if(word.length() > 15)
            {
                String value = map.get("B");
                if(value == null)
                    map.put("B", i+"@"+word.length());                
                else
                    map.put("B", value+"*"+i+"@"+word.length());
            }
        }
                
        for(int i = 0; i < message.length(); i++)
        {                
            char c = message.charAt(i);            
            if(Character.isDigit(c)||(c+"").equals(" "))
            {                
                continue;
            }
            if(Character.isUpperCase(c) && caps.equals('A'+""))
            {                
                String value = map.get(caps);
                if(value == null || value.trim().equals(""))
                    map.put(caps+"", i+"");
                else
                    map.put(caps+"", value+"*"+i);
                continue;
            }
            if(Character.isLowerCase(c) && caps.equals('a'+""))
            {                
                String value = map.get(caps);
                if(value == null || value.trim().equals(""))
                    map.put(caps+"", i+"");
                else
                    map.put(caps+"", value+"*"+i);
                continue;
            }
            
            if(!Character.isAlphabetic(c) && !Character.isDigit(c))
            {
                String value = i+"";
                if(map.keySet().contains(c+""))
                {
                    value = map.get(c+"")+"*"+value;
                }
                map.put(c+"", value);
                continue;
            }                                     
        }
        
        
        //map to string
        String out = "";
        for(String key: map.keySet())
        {
            out+=key+"^"+map.get(key)+" ";
        }
        
        return out;
    }
    
    private static void shuffle(ArrayList<String> arr, int key)
    {
        int size = arr.size();
        int[] exchanges = getShuffleExchanges(size, key);
        for (int i = size - 1; i > 0; i--)
        {
            int n = exchanges[size - 1 - i];
            String tmp = arr.get(i);
            arr.set(i, arr.get(n)); 
            arr.set(n,tmp);       
        }        
    }
    
    private static int[] getShuffleExchanges(int size, int key)
    {
        int[] exchanges = new int[size - 1];
        Random rand = new Random(key);
        for (int i = size - 1; i > 0; i--)
        {
            int n = rand.nextInt(i + 1);
            exchanges[size - 1 - i] = n;
        }
        return exchanges;
    }
    
    private static int keyIntoInt(Key key)
    {
        long value = 0;
        for (int i = 0; i < key.getEncoded().length; i++)
        {
            value = (value << 8) + (key.getEncoded()[i] & 0xff);
        }        
        return (int) (value / Integer.MAX_VALUE);
    }
    
    private static void extractWords(String message, ArrayList<String> words) throws FileNotFoundException 
    {              
        Scanner scan = new Scanner(message);
        while(scan.hasNext())
        {
            String word = scan.next();
            //normalize text
            word = word.toLowerCase();            
            word = word.replaceAll("[^A-Za-z0-9àáãâéèêíìîóòôõúùûñç]", "");

            if(!word.trim().equals(""))
            {         
                words.add(word);
            }
        }        
    }
    
    private static void extractTrapdoors(String ciphered, ArrayList<String> cifras) throws FileNotFoundException 
    {                
        String[] cipherArr;
        cipherArr = ciphered.split(" ");        
        cifras.addAll(Arrays.asList(cipherArr));        
        cifras.remove("");
    }
    
    private static String[] splitCipher(String cifra,int blockSize)
    {       
        ArrayList<String> out = new ArrayList<>();
        ArrayList<String> subcifras = new ArrayList<>();
        if(cifra.length() > trapdoorMaxSize)
        {            
            for (int i = 0; i < cifra.length(); i+=trapdoorMaxSize) 
            {
                subcifras.add(cifra.substring(i, i+trapdoorMaxSize));
            }            
        }                        
        else
        {
            subcifras.add(cifra);
        }        
        for (String subCifra : subcifras) 
        {
            out.addAll(Arrays.asList(atomicSplitCipher(subCifra, blockSize)));
        }                
        String[] outArr = new String[out.size()];        
        return out.toArray(outArr);
    }
    
    private static String[] atomicSplitCipher(String cifra, int blockSize)
    {
        int blocks = cifra.length() / blockSize;
        String[] subs = new String[blocks];
        for(int i = 0; i < blocks; i++)
        {            
            subs[i] = cifra.substring(i*blockSize, i*blockSize+blockSize);            
        }
        return subs;
    }
    
    
    private static int getnSubcifras(double len)
    {
        return (int)Math.ceil(len/15.0);
    }

    private static String getBTag(String metadata) 
    {        
        HashMap<String,String> map = new HashMap<>(); 
        try 
        {
            getHashMap(metadata, map);
        }
        catch (Exception ex) 
        {
            Logger.getLogger(PPSE.class.getName()).log(Level.SEVERE, null, ex);
        }
        return map.get("B");
    }
}
