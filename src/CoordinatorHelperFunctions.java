//package pl.payu.coordinator.main;
import java.util.*;
import java.io.*;
import java.io.File;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import java.io.ByteArrayInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern; 

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.payu.coordinator.main.security.crypto.Crypto; 

public class CoordinatorHelperFunctions {

	final static Logger LOGGER = LoggerFactory.getLogger(CoordinatorHelperFunctions.class);
	
	//<OrderCreateRequest xsi:type="TransparentOrderCreateRequest">         <ExtOrderId>ExtOrderId0</ExtOrderId>         <CustomerIp>127.0.0.1</CustomerIp>         <MerchantPosId>OPU_DEMO</MerchantPosId>         <Description>Description0</Description>         <CurrencyCode>PLN</CurrencyCode>         <TotalAmount>555</TotalAmount>         <Buyer>             <Email>ABC@DEF.PL</Email>             <Phone>PhoneNumber</Phone>             <FirstName>FirstName</FirstName>             <LastName>LastName</LastName>             <Language>en</Language>             <NIN>88810885312</NIN>         </Buyer>         <Products>             <Product>                 <Name>Name0</Name>                 <UnitPrice>20</UnitPrice>                 <Quantity>2</Quantity>             </Product>             <Product>                 <Name>Name1</Name>                 <UnitPrice>10</UnitPrice>                 <Quantity>1</Quantity>             </Product>         </Products>         <PayMethods>             <PayMethod>                 <Type>CARD_TOKEN</Type>                 <Value>{SINGLE_USE_TOKEN}</Value>             </PayMethod>
	private static Pattern regexMessageInfo = Pattern.compile("<(\\w+)(Request|NotifyAsync)\\s+Version=\"(2.0)\">\\s*<ReqId>(.+?)</ReqId>");
	private static Pattern regexMessageName = Pattern.compile("<(payu:|)(\\w+)(Create|Delete|Retrieve|Cancel|Update|Notify)(Request|Async)");
	private static Pattern regexMessageReqId = Pattern.compile("<ReqId>(.+?)</ReqId>");
	//private static Pattern regex = Pattern.compile("<(\\w+)Request\\s+Version=\"2.0\">");
	
	public static String getMessageInfo(String message) {
		//System.out.println("----------------CoordinatorHelperFunctions----------------");
		//System.out.println(message);
		//final String s = "killing of <span class=\"abc\">cats</span>, "	+ "hi <span class=\"xyz\">dogs</span>,";
		long start = System. currentTimeMillis();
		
		//***********************WebService
		Matcher matcher = regexMessageInfo.matcher(message);
		String[] resultArray = new String[5];
		String result="";
		if (matcher.find()) {
		  resultArray[0] = matcher.group(1); //Nazwa komunikatu z metodą np. OrderCreate
		  resultArray[1] = matcher.group(2); //Tryb komunikacji np. Request / Async
		  resultArray[2] = matcher.group(3); //Version
		  resultArray[3] = matcher.group(4); //ReqId
		} else {
		  
		  //***********************Rest
		  Matcher matcherName = regexMessageName.matcher(message);
		  if (matcherName.find()) {
			//resultArray[ ] = matcherName.group(1); zignorowanie ewentualnego prefiksu
			resultArray[0] = matcherName.group(2) + matcherName.group(3); //Nazwa komunikatu z metodą np. OrderCreate
			resultArray[1] = matcherName.group(4);						  //Tryb komunikacji np. Request / Async		
		  } else {
			resultArray[0] = "Unknown"; //Message
			resultArray[1] = "Unknown"; //Message
		  }

		  resultArray[2] = "2.0"; //Version - wartość domyślna ze schemy

		  Matcher matcherReqId = regexMessageReqId.matcher(message);
		  if (matcherName.find()) {
			resultArray[3] = matcherReqId.group(1);
		  } else {
			resultArray[3] = "1";	  //ReqId	  
		  }
		  
		}
		result= resultArray[0] +"|" + resultArray[1] + "|" + resultArray[2] +"|" + resultArray[3] +"|";
		System.out.println(""+result + "\ttime=" + (System.currentTimeMillis() - start));
		

		return result;
	};
	//OpenPayuSignature:sender=11111;signature=69d82f61184e782f611812282f6118fa069dfcdf;algorithm=SHA-1;content=DOCUMENT
	private static Pattern regexHeaderParams = Pattern.compile("openpayusignature: sender=(.+?);signature=(.+?) ;algorithm=(.+?);content=DOCUMENT");

	public static String getHeaderParams(String message) {
		//System.out.println("----------------CoordinatorHelperFunctions----------------");
		long start = System. currentTimeMillis();
		
		Matcher matcher = regexHeaderParams.matcher(message);
		String[] resultArray = new String[3];
		String result="";
		if (matcher.find()) {
		  resultArray[0] = matcher.group(1);
		  resultArray[1] = matcher.group(2);
		  resultArray[2] = matcher.group(3);
		} else {
		  resultArray[0] = "UnknownHeader";
		  resultArray[1] = "null";
		  resultArray[2] = "null";		  
		}
		result= resultArray[0] +"|" + resultArray[1] +"|" + resultArray[2];
		System.out.println(""+result);
		//System.out.println("time = " + period);

		return result;
	};

	public static String getUUID() {
		return UUID.randomUUID().toString().replaceAll("-", "");
	}

	
    public static String verifySignature(String expectedSignature, String serializedDocument, String key, String algorithm) {
	
		try {
			serializedDocument = serializedDocument.trim();
			key = key.trim();
			String calculatedSignature = Crypto.generateHash(serializedDocument + key, algorithm);
			LOGGER.warn("------------------");
			LOGGER.warn("key='{}'", key);
			LOGGER.warn("serializedDocument='{}'", serializedDocument);
			LOGGER.warn("------------------");
			LOGGER.warn("expectedSignature='{}' ? calculatedSignature='{}'", expectedSignature, calculatedSignature);

			if (calculatedSignature == null || !calculatedSignature.equals(expectedSignature)) {
				LOGGER.warn("Invalid signature. expectedSignature != calculatedSignature - {} != {}", expectedSignature, calculatedSignature);
				return "INVALID";
			}
        } catch (Exception e) {
            LOGGER.error("verifySignature [algorithm={},error={}]", new Object[] { algorithm, e });
            return "INVALID";
        }
       
        return "VALID";
    }

	
	
	  /**
      * The following is a two-dimensional array that provides the
      * online help for functions in this class. Declare an array
      * named HELP_STRINGS.
      */
      public static final String[][] HELP_STRINGS ={
         {"getMessageInfo", "Funkcja wyszukuje w komunikacie OPY jego nazwę np. CustomerCreateRequest", "getMessageInfo()","yes"},
		 {"getHeaderParams", "Funkcja wyszukuje w Headerze POST następujących parametrów: sender, signature, algorithm", "getHeaderParams()"},
		 {"getUUID", "Funkcja generuje 32 znakowe unikalne ID bez formatowania", "c6f41aeb64064480b0db6e8dfaa999d7", ""},
		 {"verifySignature", "Funkcja weryfikujaca podpis pod komunikatem OPY", "verifySignature(expectedSignature, serializedDocument, key, algorithm)", "VALID"}
	  };	

	/********************** Funkcje przydatne do testowania **********************/ 
	
	private static String readFile( String file ) throws IOException {
		System.out.println("file::"+file);
		BufferedReader reader = new BufferedReader( new FileReader (file));
		String         line = null;
		StringBuilder  stringBuilder = new StringBuilder();
		String         ls = System.getProperty("line.separator");

		while( ( line = reader.readLine() ) != null ) {
			stringBuilder.append( line );
			//stringBuilder.append( ls );
		}
		//System.out.println(stringBuilder.toString());
		return stringBuilder.toString();
		//return reader;
	}	
		

		
		
	public static void main(String args[]) {
		try {
			
			//getHeaderParams(readFile("c:\\repos\\coordinator-tibco\\java\\tests\\Header.txt"));
			getMessageInfo(readFile("c:\\repos\\coordinator-tibco\\java\\tests\\CustomerCreateRequest1.xml"));
			getMessageInfo(readFile("c:\\repos\\coordinator-tibco\\java\\tests\\CustomerCreateRequest2.xml"));
			getMessageInfo(readFile("c:\\repos\\coordinator-tibco\\java\\tests\\OrderCreateRequest.xml"));
			getMessageInfo(readFile("c:\\repos\\coordinator-tibco\\java\\tests\\OrderCreateRequest-rest.xml"));
			getMessageInfo(readFile("c:\\repos\\coordinator-tibco\\java\\tests\\AccountBalanceNotifyAsync.xml"));			
			System.out.println("UUID = "+getUUID());
			//String expectedSignature = "87ea27035319feafbdc2a7419fa64439c8400d03";
			//String expectedSignature = "1578c2e0a0d0424f6419805d2307ef0e917c7cdb";
			//String serializedDocument = readFile("c:\\repos\\coordinator-tibco\\java\\tests\\CustomerCreateRequest1.xml");
			//String key = "6a204bd89f3c8348afd5c77c717a097a";
			//String algorithm = "SHA-1";
			//LOGGER.info("expectedSignature = '{}'",expectedSignature);
			//LOGGER.info("serializedDocument = '{}'",serializedDocument);
			//LOGGER.info("key = '{}'",key);
			//LOGGER.info("algorithm = '{}'",algorithm);
			//LOGGER.info("verifySignature = '{}'",verifySignature(expectedSignature, serializedDocument, key, algorithm));
			
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}
}