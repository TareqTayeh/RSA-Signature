package Security;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class sign {	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		Scanner reader = new Scanner(System.in);  // Reading from System.in
		
		//Reading filename entered by user, and storing text data in a string
		System.out.println("Enter Filename: ");
		String filename = reader.next();
		//filename (for me) = C:\\Users\\ttayeh\\eclipse-workspace\\SE4472Assignment2Question1\\src\\Security\\sign.java
		String fileData;
		BufferedReader br = new BufferedReader(new FileReader(filename));
		try {
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();

		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		    }
		    fileData = sb.toString();
		} finally {
		    br.close();
		}
		
		//Reading private signing key (n,d) entered by user
		System.out.println("n: ");
		String nString = reader.next();
		System.out.println("d: ");
		String dString = reader.next();
		BigInteger n = new BigInteger(nString);
		BigInteger d = new BigInteger(dString);
//		n = 96593720236010659771827402676643429789938619440952555364622074956435340200061656508060615789030840134203664978505512524142393395270050853990539724973005030936743555266850207882401594704734189906511529782800955972664184033920361943962669563041630205806431828596746559268709959974499729037311769911690888754219
//		d = 17487594650354249938091950085575694561203926326607901939381432158293869287177190815388852195505606271149525992492300625584776502355602993463200235543352678006383997467860705323250971456335829396517506516991764156256889079821612990896638819945492250519738119781570884479786708912307843283470457443387159862073
		
		//Hashing message in java file using SHA-256
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(fileData.getBytes());
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        String hashedString = hexString.toString();
        int hashedStringBitLength = hexString.toString().length()*4;
        System.out.println("Hashed Message: " + hashedString);
        System.out.println("Hashed Message Bit length: " + hashedStringBitLength + "\n");
        
        //Storing ASN.1	encoding header specifying the SHA256 hash algorithm
        String asn1 = "3031300d060960864801650304020105000420";
        int asn1BitLength = asn1.length()*4;
        System.out.println("ASN.1: " + asn1);
        System.out.println("ASN.1 Bit length: " + asn1BitLength + "\n");
        
        //Find n in bits
        int nBitLength = n.bitLength();
        System.out.println("n in bits: " + nBitLength + "\n");
        
        //Find how many bits left for PKSC1 v1.5
        int pkcs1bits = nBitLength - (hashedStringBitLength + asn1BitLength);
        System.out.println("# of Bits left for pkcs1: " + pkcs1bits);
        
        // pkcs1 = "1FFF.......00"
        String pkcs1 = "1";
        int loopMax = (pkcs1bits/4) - 3; //Divide by 4 as each char is 4 bits, and -3 to take into account the leading number and trailing 2 numbers
        for (int i = 0; i < loopMax; i++) {
        	pkcs1 = pkcs1.concat("F");
        }
        pkcs1 = pkcs1.concat("00");
        System.out.println("Pkcs1: " + pkcs1 + "\n");
        
        //Build message string = [pkcs1 + asn1 + SHA256 of file]
        String message = pkcs1;
        message = message.concat(asn1);
        message = message.concat(hashedString);
        int messageBitLength = message.length()*4;
        System.out.println("Message: " + message);
        System.out.println("Message Bit length: " + messageBitLength + "\n");
        
        //s = (m^d) mod n 
        //Raising message to exponent 'd', the private key, then mod 'n' to get the signature 's'
        BigInteger s = new BigInteger(message,16);
        s = s.modPow(d,n);
        String signature = new BigInteger(s.toString()).toString(16);
        int signatureBitLength = signature.length()*4;
        System.out.println("Signature: " + signature);
        System.out.println("Signature Bit length: " + signatureBitLength + "\n");
        
        //(s^e) mod n should equal m
        //Raising signature to exponent 'e', the public key, then mod 'n' to get the message
        BigInteger e = new BigInteger("65537");
        BigInteger m = s.modPow(e, n);
        String messageCheck = new BigInteger(m.toString()).toString(16);
        int messageCheckBitLength = messageCheck.length()*4;
        System.out.println("Message Check: " + messageCheck);
        System.out.println("Message Check Bit length: " + messageCheckBitLength);
		
		reader.close(); //Closing reader
		
	}	
}