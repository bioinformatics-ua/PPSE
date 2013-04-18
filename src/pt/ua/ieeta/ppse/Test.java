/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package pt.ua.ieeta.ppse;

import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

/**
 *
 * @author Luís S. Ribeiro
 */
public class Test 
{
    private static byte[] toByte (String hex)
    {

        byte[] bts = new byte[hex.length() / 2];
        for (int i = 0; i < bts.length; i++)
        {
            bts[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }

        return bts;
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
    public static void main(String[] args) throws IOException
    {
        
        String metaCipher = "54a83708e39f31537afaf897be024f47a90888a60e0541fadeee01a9eb053d3bd5a7bf3ce8c4308ba51403fcdf783591806c1142a9d9568c87febbdca4489884";
        byte[] metaByte = toByte(metaCipher);
        
        
//        GZIPInputStream gis = new GZIPInputStream(new ByteInputStream(metaByte, metaByte.length));
//        gis.
//        gis.read(metaByte);
//        gis.close();
        
        
        
        
//        int b = 2;
//        int[] len = {16,31,50};
//        int[] idxs = {1,3,5};
//        ArrayList<String> arr = new ArrayList<>(Arrays.asList(new String[] {"OOOO","XXXX","XXXX","OOOO","XXXX","XXXX","XXXX","OOOO","XXXX","XXXX","XXXX","XXXX","OOOO","OOOO"}));
//        
//               
//        for (int i = 0; i < idxs.length; i++) 
//        {
//            int idx = idxs[i];
//            int nWord = getnSubcifras(len[i]);
//            System.err.println(nWord);
//            arr = mergeCells(arr, idx, idx + nWord);
//        }
//        
//        for (String string : arr) {
//            System.out.println(string);
//        }
        
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
    
    private static int getnSubcifras(double len)
    {
        
        return (int)Math.ceil(len/15.0);
    }
}
