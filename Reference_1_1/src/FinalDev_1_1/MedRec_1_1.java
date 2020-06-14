package FinalDev_1_1;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class MedRec_1_1 extends Applet{
//--CLA DAN INS-----------------------------------------------------------------------//
//--//DATA MANAGEMENT
	//--CLA
	final static byte Keamanan_CLA =(byte)0x70;
    final static byte Text_CLA =(byte)0x80;
    final static byte Num_CLA =(byte)0x90;
    
    //--INS
    final static byte INS_INPUT = (byte) 0x30;
    final static byte INS_DELETE = (byte) 0x40;
    final static byte INS_GET_DATA = (byte) 0x50;
    
    final static byte INS_GET_TYPE = (byte) 0x21;
    final static byte INS_GET_ITEM = (byte) 0x22;
    
    final static byte INS_GET_MAX_FIELD  = (byte) 0x60;
    final static byte INS_GET_MAX_VAL  = (byte) 0x61;
    
    final static byte INS_GET_MIN_FIELD = (byte) 0x70;
    final static byte INS_GET_MIN_VAL = (byte) 0x71;
    
    final static byte INS_GET_FIELD = (byte) 0x80;
    final static byte INS_GET_STACK = (byte) 0x90;
    
    final static byte INS_REGISTER_DINAMIS = (byte) 0x10;
    final static byte INS_GET_LEN = (byte) 0x20;
    
    final static byte INS_OBJECT_DELETION = (byte) 0xD0;
	
//--//PIN MANAGEMENT
	//--INS
    final static byte INS_VERIFY_USER = (byte) 0xA0;
    final static byte INS_VERIFY_ADMIN = (byte) 0xA1;
    final static byte INS_VERIFY_DOKTER = (byte) 0xA2;
    final static byte INS_VERIFY_OPERATOR = (byte) 0xA3;

    final static byte INS_UPDATE_USER_PIN = (byte) 0xB0;
    final static byte INS_UPDATE_ADMIN_PIN = (byte) 0xB1;
    final static byte INS_UPDATE_DOKTER_PIN = (byte) 0xB2;
    final static byte INS_UPDATE_OPERATOR_PIN = (byte) 0xB3;
	
//--//KRIPTOGRAFI
	//
    final static byte INS_GET_DATA_PADDED = (byte) 0xE0;
	final static byte REMOVE_PAD = (byte) 0xE1;
	
//--SW STATUS-----------------------------------------------------------------------//
	//DATA MANAGEMENT
    final static short SW_INVALID_DATA_INPUT_FIELD = 0x6A80;
    final static short SW_INVALID_DATA_INPUT_RANGE = 0x6A87;
    final static short SW_FIELD_NOT_EMPTY = 0x6A84;
    //final static short SW_INS_NOT_ALLOWED = 0x6A85;
    //final static short SW_DATA_NOT_CREATED = 0x6A86;
    
	//PIN MANAGEMENT
    //--Need Verifikasi
    final static short SW_USER_PIN_VERIFICATION_REQUIRED =0x6300;
    final static short SW_ADMIN_PIN_VERIFICATION_REQUIRED =0x6301;
    final static short SW_DOKTER_PIN_VERIFICATION_REQUIRED =0x6302;
    final static short SW_OPERATOR_PIN_VERIFICATION_REQUIRED =0x6303;
    final static short SW_ROLE_PIN_VERIFICATION_REQUIRED =0x6304;
    //--Verifikasi Gagal
    static short SW_VERIFICATION_FAILED = 0x63C0;
    //--Fungsionalitas kartu dikunci
    final static short SW_CARD_LOCKED = 0x6900;
    
	//KRIPTOGRAFI
	//--X
	//--X
	
//--PARAMETER DATA-----------------------------------------------------------------------//
//--//DATA MANAGEMENT
    //--jumlah item per tipe data
  	final static short MAX_ITEM_DATADIRI = 46;
  	final static short MAX_ITEM_STATIS = 7;
  	final static short MAX_ITEM_DINAMIS = 48;
  	final static short MAX_STACK = 20;
	
  	//--parameter statField datadiri dan statis NUM
    private byte[] statField_DATA = new byte[MAX_ITEM_DATADIRI];
  	private byte[] statField_STATIS = new byte[MAX_ITEM_STATIS];
    
    //--parameter MAX VAL tiap item untuk inisiasi
  	private short[] MAX_VAL_DATA = new short[MAX_ITEM_DATADIRI];
  	private short[] MAX_VAL_STATIS = new short[MAX_ITEM_STATIS];
  	private short[] MAX_VAL_DINAMIS = new short[MAX_ITEM_DINAMIS];
    
    //--parameter MIN VAL tiap item untuk inisiasi
  	private short[] MIN_VAL_DATA = new short[MAX_ITEM_DATADIRI];
  	private short[] MIN_VAL_STATIS = new short[MAX_ITEM_STATIS];
  	private short[] MIN_VAL_DINAMIS = new short[MAX_ITEM_DINAMIS];
  	
    //--parameter MAX VAL tiap item untuk inisiasi
  	private short[] MAX_FIELD_DATA = new short[MAX_ITEM_DATADIRI];
  	private short[] MAX_FIELD_STATIS = new short[MAX_ITEM_STATIS];
  	private short[] MAX_FIELD_DINAMIS = new short[MAX_ITEM_DINAMIS];
    
    //--parameter MIN FIELD tiap item untuk inisiasi
  	private short[] MIN_FIELD_DATA = new short[MAX_ITEM_DATADIRI];
  	private short[] MIN_FIELD_STATIS = new short[MAX_ITEM_STATIS];
  	private short[] MIN_FIELD_DINAMIS = new short[MAX_ITEM_DINAMIS];
	
//--//PIN MANAGEMENT
  	//--batas maksimal percobaan verifikasi 
    final static byte PIN_TRY_LIMIT_USER_USER =(byte)0x05;
    final static byte PIN_TRY_LIMIT_USER_ROLE =(byte)0x10;
    //--ukuran maksimal pin
    final static byte MAX_PIN_SIZE_USER =(byte)0x08;
    final static byte MAX_PIN_SIZE_ROLE =(byte)0x10;
    
//--//KRIPTOGRAFI
	//--X
	//--X
	
//--DEKLARASI VARIABLE PROSES-----------------------------------------------------------------------//	
//--//DATA MANAGEMENT
	//--X
	//--indeks tipe data
	final static byte indeksDATA = (byte) 0x00;
	final static byte indeksSTATIS = (byte) 0x01;
	final static byte indeksDINAMIS = (byte) 0x02;
	
	//--inisiasi objek data
	private IsiDataTEXT[] dataDiri;
	private IsiDataTEXT[] dataStatis;
	private ItemDinamisTEXT[] dataDinamis;
	
	//--variabel temp proses data
	byte[] dataText;
	short dataNumProcess;
	
	//--variabel proses lainnya
	byte type;
    byte item;
    short maxVal;
    short minVal;
    short minField;
    short maxField;
    short stack = (short) 1;
    short lenData;
    
    byte statField;
    
//--//PIN MANAGEMENT
    //--deklarasi pin
    OwnerPIN pin;
    OwnerPIN pinAdmin;
    OwnerPIN pinDokter;
    OwnerPIN pinOperator;
	//--buffer
    byte[] bufferData;
    byte[] dataStored;
    byte[] dataPadded;
    short 	len_dataPadded;
    
//--//KRIPTOGRAFI
    //--Inisiasi Kunci
    private byte aesKeyLen;
    private byte[] aesKey;
    private byte[] aesICV;
    //--metode enkripsi
    private Cipher aesEcbCipher;
    private Cipher aesCbcCipher;
    //--variabel inisiasi kunci saat instalasi
    private Key tempAesKey1;
    private Key tempAesKey2;
    private Key tempAesKey3;
    //--Parameter kunsi Enkripsi
    private byte keyLen = (byte)32;
    //--Indeks Metode Enkripsi
    private byte Enc = 0x00;
    private byte Dec = 0x01;
    //--Random Data untuk "salt"
    private RandomData randomData;
    private byte[] rnd_key;
    private byte[] rnd_IV;
	

//--PROSES INSTALASI APPLET-----------------------------------------------------------------------//
//--//MAIN METHOD APPLET (KONSTRUKTOR)
    private MedRec_1_1 (byte[] bArray,short bOffset,byte bLength) {
    //--DATA MANAGEMENT-----------------------------------------------------------------------//
    //--//INISIASI DATA
        //--Inisiasi parameter
    	InisiasiStatField();
    	InisiasiMinVal();
    	InisiasiMaxVal();
    	InisiasiMinField();
    	InisiasiMaxField();
    	//--Inisiasi data
    	InisiasiDataTEXT();
    	
    //--PIN MANAGEMENT-----------------------------------------------------------------------//
    //--//INISIASI PIN
    	//--Inisiasi Variabel Pin
        pin = new OwnerPIN(PIN_TRY_LIMIT_USER_USER,   MAX_PIN_SIZE_USER);
        pinAdmin = new OwnerPIN(PIN_TRY_LIMIT_USER_ROLE,   MAX_PIN_SIZE_ROLE);
        pinDokter = new OwnerPIN(PIN_TRY_LIMIT_USER_ROLE,   MAX_PIN_SIZE_ROLE);
        pinOperator = new OwnerPIN(PIN_TRY_LIMIT_USER_ROLE,   MAX_PIN_SIZE_ROLE);
    	//--Paramater Instalasi Pin
        //FORMAT PARAMETER APDU: lenPinrole pinrole (user-admin-dokter-operator)
        //CONTOH PARAMETER: 03 11 22 33 10 10 20 30 40 50 60 70 80 90 00 10 20 30 40 50 60 10 11 21 31 41 51 61 71 81 91 01 11 21 31 41 51 61 10 12 22 32 42 52 62 72 82 92 02 12 22 32 42 52 62 
        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset+iLen+1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset+cLen+1);
        byte aLen = bArray[bOffset]; // applet data length
        bOffset = (short) (bOffset+1);
    	
    //--//UPDATE PIN
        //--start of secure transaction
        JCSystem.beginTransaction();
    	//--User Pin
        byte userLen = bArray[bOffset];
        pin.update(bArray, (short)(bOffset+1), userLen);
    	//--Admin PIn
        bOffset = (short) (bOffset+userLen+1);
        byte adminLen = bArray[bOffset];
        if (adminLen != (byte) 0x10){
        	ISOException.throwIt (ISO7816.SW_WRONG_DATA);
        }
        pinAdmin.update(bArray, (short)(bOffset+1), adminLen);
    	//--Dokter Pin
        bOffset = (short) (bOffset+adminLen+1);
        byte dokterLen = bArray[bOffset];
        if (dokterLen != (byte) 0x10){
        	ISOException.throwIt (ISO7816.SW_WRONG_DATA);
        }
        pinDokter.update(bArray, (short)(bOffset+1), dokterLen);
    	//--Operator Pin
        bOffset = (short) (bOffset+dokterLen+1);
        byte opLen = bArray[bOffset];
        if (opLen != (byte) 0x10){
        	ISOException.throwIt (ISO7816.SW_WRONG_DATA);
        }
        pinOperator.update(bArray, (short)(bOffset+1), opLen);
        //--end of secure transaction
        JCSystem.beginTransaction();
    	
    //--KRIPTOGRAFI-----------------------------------------------------------------------//
    //--//INISIASI VARIABEL KRIPTOGRAFI
    	//--Inisiasi kunci
        aesKey = new byte[32];
        aesICV = new byte[16];
        aesKeyLen = 0;
        //--Create a AES ECB/CBS object instance of the AES algorithm.
        aesEcbCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        aesCbcCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        //--Create uninitialized cryptographic keys for AES algorithms
        tempAesKey1 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        tempAesKey2 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_192, false);
        tempAesKey3 = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256, false);
 
        JCSystem.requestObjectDeletion();
    //--//RANDOM DATA
    	//--Generator Random Data
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    	//--Random data untuk key
        short RND_LENGTH_KEY = (short)(32 - userLen);
        rnd_key = JCSystem.makeTransientByteArray(RND_LENGTH_KEY, JCSystem.CLEAR_ON_RESET);
        
        randomData.generateData(rnd_key, (short) 0, RND_LENGTH_KEY);
        //--Random data untuk IV
        short RND_LENGTH_IV = (short) 16;
        rnd_IV = JCSystem.makeTransientByteArray(RND_LENGTH_IV, JCSystem.CLEAR_ON_RESET);
        
        randomData.generateData(rnd_IV, (short) 0, RND_LENGTH_IV);
    	
    //--//UPDATE KEY KRIPTOGRAFI
    	//--start of secure transaction
        JCSystem.beginTransaction();
        //--update key
        Util.arrayCopy(bArray, (short)(bOffset+1), aesKey, (short)0, userLen);//pin
        Util.arrayCopy(rnd_key, (short)0, aesKey,  userLen, RND_LENGTH_KEY);//"salt"
    	//--update iv
        Util.arrayCopy(rnd_IV, (short)0, aesICV, (short)0, (short)16);//IV
        //--end of secure transaction
    	
        //--Static Key untuk testing modular fungsi kriptorafi dan keamanan
//      //static key
//      //key: 0102030405060708010203040506070801020304050607080102030405060708
//      //ICV: 01020304050607080102030405060708
//      
//      aesKey = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
//      aesICV = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
//      //end of static key
        
        aesKeyLen = keyLen;
        JCSystem.commitTransaction();
    //--REGISTER-----------------------------------------------------------------------//
    	register();
        
    }
//--//REGISTER
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MedRec_1_1(bArray, bOffset, bLength);
    } 
//--//SELECT
    public boolean select() {
        return true;
    }  
//--//DESELECT
    public void deselect() {
    	 pin.reset();
    }

//--PROCESS APDU-----------------------------------------------------------------------//
//--//MAIN PROCESS
    public void process(APDU apdu) {
    	// check SELECT APDU command
    	byte[] buffer = apdu.getBuffer();
        //cek aid
        if (apdu.isISOInterindustryCLA()) {
            if (buffer[ISO7816.OFFSET_INS] == (byte)(0xA4)) {
                return;
            } else {
                ISOException.throwIt (ISO7816.SW_CLA_NOT_SUPPORTED);
            }
        }
        
        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_OBJECT_DELETION:
        	JCSystem.requestObjectDeletion();
            return;
        default:
        	break; //command not allowed
    	}
        
        if (pin.getTriesRemaining() == 0){
        	switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_VERIFY_ADMIN:
                verifyAdmin(apdu);
                return;
            case INS_UPDATE_USER_PIN:
                updatePin(apdu);
                return;
            default:
            	ISOException.throwIt(SW_CARD_LOCKED); //command not allowed
        	}
        }
        
        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_VERIFY_USER:
            verifyUser(apdu);
            return;
        case INS_VERIFY_ADMIN:
            verifyAdmin(apdu);
            return;
        case INS_UPDATE_USER_PIN:
            updatePin(apdu);
            return;
        default:
        	break;
        }
        
        //fungsi lain membutuhkan verifikasi user pin
    	if ( ! pin.isValidated() ){
            ISOException.throwIt(SW_USER_PIN_VERIFICATION_REQUIRED);
    	}
        
        switch (buffer[ISO7816.OFFSET_INS]) { 
        case INS_VERIFY_DOKTER:
            verifyDokter(apdu);
            return;
        case INS_VERIFY_OPERATOR:
            verifyOperator(apdu);
            return;
        case INS_UPDATE_ADMIN_PIN:
        	updatePinAdmin(apdu);
        	return;
        case INS_UPDATE_DOKTER_PIN:
        	updatePinDokter(apdu);
        	return;
        case INS_UPDATE_OPERATOR_PIN:
        	updatePinOperator(apdu);
        	return;
        case INS_VERIFY_ADMIN:
            verifyAdmin(apdu);
            return;
        default:
            break;
        }  
        //cek CLA atau jenis data
        switch (buffer[ISO7816.OFFSET_CLA]){
//        case Keamanan_CLA:
//        	ISOException.throwIt((short) 0x0101);
//        	return;
        case Text_CLA:
            processTEXT(apdu, buffer);
            return;
        case Num_CLA:
        	processNUM(apdu,buffer);
        	return;
        default:
        	ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }  
        
    }    
//--//TEXT PROCESS
    private void processTEXT(APDU apdu,byte[] buffer ){
    	//INS operasi khusus dinamis tidak memiliki type/item
    	switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_REGISTER_DINAMIS:
        	if (!pinAdmin.isValidated() && !pinDokter.isValidated())
        	{
                ISOException.throwIt(SW_DOKTER_PIN_VERIFICATION_REQUIRED);
        	}
            registerDinamis(apdu);
            return;
        case INS_GET_STACK:
        	getStack(apdu);
            return;
        case INS_GET_DATA_PADDED:
        	getDataPadded(apdu);
        	return;
        default:
            break;
        }
    	
    	//mengambil nilai item dan type
    	type = buffer[ISO7816.OFFSET_P1]; // 0/1/3
        item = buffer[ISO7816.OFFSET_P2]; // No. urut data pada excell
        								  // mulai dari 0
        
        //Mendapatkan parameter data
        //indeks yang salah pda input (data tidak terdaftar)
        //akan mengakibatkan overflow sehingga exeption dibutuhkan
        try{
        	switch (type) {
	        case indeksDATA:
	        	minField = (short) MIN_FIELD_DATA[item];
	        	maxField = (short) MAX_FIELD_DATA[item];
	        	statField = dataDiri[item].getStat(); 
	            break;
	        case indeksSTATIS:
	        	minField = (short) MIN_FIELD_STATIS[item];
	        	maxField = (short) MAX_FIELD_STATIS[item];
	        	statField = dataStatis[item].getStat();
	            break;
	        case indeksDINAMIS:
	        	minField = (short) MIN_FIELD_DINAMIS[item];
	        	maxField = (short) MAX_FIELD_DINAMIS[item];
	        	statField = dataDinamis[stack].getStat(item);
	            break;
	        default:
	        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
	        }
        }catch(Exception e){
        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }

        //INS operasi TEXT
        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_GET_DATA:
        	if ( !pinAdmin.isValidated() && !pinDokter.isValidated() && !pinOperator.isValidated() )
        	{
                ISOException.throwIt(SW_ROLE_PIN_VERIFICATION_REQUIRED);
        	}
            getDataTEXT(apdu);
            return;
        case INS_DELETE:
        	if(type == indeksDATA){
        		if ( !pinAdmin.isValidated()){
        			ISOException.throwIt(SW_ADMIN_PIN_VERIFICATION_REQUIRED);}
        	}else{
        		if (!pinAdmin.isValidated() && !pinDokter.isValidated()){
        			ISOException.throwIt(SW_DOKTER_PIN_VERIFICATION_REQUIRED);}
        	}
            deleteDataTEXT(apdu);
            return;
        case INS_INPUT:
        	if(type == indeksDATA){
        		if ( !pinAdmin.isValidated()){
        			ISOException.throwIt(SW_ADMIN_PIN_VERIFICATION_REQUIRED);}
        	}else{
        		if (!pinAdmin.isValidated() && !pinDokter.isValidated()){
        			ISOException.throwIt(SW_DOKTER_PIN_VERIFICATION_REQUIRED);}
        	}
            inputTEXT(apdu);
            return;
        case INS_GET_LEN:
            getLenDataStored(apdu);
            return;
        case INS_GET_MAX_FIELD:
        	getMaxField(apdu);
            return;
        case INS_GET_MIN_FIELD:
        	getMinField(apdu);
            return;
        case INS_GET_FIELD:
        	getField(apdu);
            return;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
//--//NUM PROCESS
    private void processNUM(APDU apdu,byte[] buffer ){
    	switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_REGISTER_DINAMIS:
        	if (!pinAdmin.isValidated() && !pinDokter.isValidated())
        	{
                ISOException.throwIt(SW_DOKTER_PIN_VERIFICATION_REQUIRED);
        	}
            registerDinamis(apdu);
            return;
        case INS_GET_STACK:
        	getStack(apdu);
            return;
        default:
            break;
        }
    	
    	//INDEKS
    	type = buffer[ISO7816.OFFSET_P1]; // 0/1/3
        item = buffer[ISO7816.OFFSET_P2]; // No. urut data pada excell
        								  // mulai dari 0
        
        //PARAM
        try{
        	switch (type) {
	        case indeksDATA:
	        	maxVal = (short) MAX_VAL_DATA[item];
	        	minVal = (short) MIN_VAL_DATA[item];
	        	maxField = (short) MAX_FIELD_DATA[item];
	        	statField = dataDiri[item].getStat();
	            break;
	        case indeksSTATIS:
	        	maxVal = (short) MAX_VAL_STATIS[item];
	        	minVal = (short) MIN_VAL_STATIS[item];
	        	maxField = (short) MAX_FIELD_STATIS[item];
	        	statField = dataStatis[item].getStat();
	            break;
	        case indeksDINAMIS:
	        	maxVal = (short) MAX_VAL_DINAMIS[item];
	        	minVal = (short) MIN_VAL_DINAMIS[item];
	        	maxField = (short) MAX_FIELD_DINAMIS[item];
	        	statField = dataDinamis[stack].getStat(item);
	            break;
	        default:
	        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
	        }
	    }catch(Exception e){
	    	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
	    }

        //INS
        switch (buffer[ISO7816.OFFSET_INS]) {
        case INS_INPUT:
        	if(type == indeksDATA){
        		if ( !pinAdmin.isValidated()){
        			ISOException.throwIt(SW_ADMIN_PIN_VERIFICATION_REQUIRED);}
        	}else{
        		if (!pinAdmin.isValidated() && !pinDokter.isValidated()){
        			ISOException.throwIt(SW_DOKTER_PIN_VERIFICATION_REQUIRED);}
        	}
            inputDataNUM(apdu);
            return;
        case INS_GET_DATA:
        	if ( !pinAdmin.isValidated() && !pinDokter.isValidated() && !pinOperator.isValidated() )
        	{
                ISOException.throwIt(SW_ROLE_PIN_VERIFICATION_REQUIRED);
        	}
            getDataNUM(apdu);
            return;
        case INS_DELETE:
        	if(type == indeksDATA){
        		if ( !pinAdmin.isValidated()){
        			ISOException.throwIt(SW_ADMIN_PIN_VERIFICATION_REQUIRED);}
        	}else{
        		if (!pinAdmin.isValidated() && !pinDokter.isValidated()){
        			ISOException.throwIt(SW_DOKTER_PIN_VERIFICATION_REQUIRED);}
        	}
            deleteDataNUM(apdu);
            return;
        case INS_GET_TYPE:
            getType(apdu);
            return;
        case INS_GET_ITEM:
        	getItem(apdu);
            return;
        case INS_GET_MAX_VAL:
        	getMaxVal(apdu);
            return;
        case INS_GET_MIN_VAL:
        	getMinVal(apdu);
            return;
        case INS_GET_MAX_FIELD:
        	getField(apdu);
            return;
        case INS_GET_STACK:
        	getStack(apdu);
            return;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
//--METODE DATA MANAGEMENT-----------------------------------------------------------------------//
//--//FUNGSI UTAMA DATA TEXT (CRUD)
    private void inputTEXT(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();
        
        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
        short byteRead = apdu.setIncomingAndReceive();

        if ( ( byteRead > maxField)
             || ( byteRead < minField ) )
            ISOException.throwIt(SW_INVALID_DATA_INPUT_FIELD);
        
        if ( statField != (byte) 0 )
               ISOException.throwIt(SW_FIELD_NOT_EMPTY);
        
      //masukin data
        byte[] bufferData = JCSystem.makeTransientByteArray((short) numBytes, JCSystem.CLEAR_ON_RESET);
       	short dataOffset = (short) 0;

        while (byteRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, bufferData, dataOffset, byteRead);
            dataOffset += byteRead;
            byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
        
        short lenData = (short) bufferData.length;
        byte[] dataPadded;
        short len_dataPadded;
        
        dataPadded = addPadtoData(bufferData);
        len_dataPadded = (short) dataPadded.length;
        
        byte[] dataStored =	JCSystem.makeTransientByteArray(len_dataPadded, JCSystem.CLEAR_ON_RESET);
        dataStored = doAesCipherFunction(Enc, len_dataPadded, dataPadded);
        short len_dataFinal = (short) dataStored.length;
        
        switch (type) {
        case indeksDATA:
        	//statField = dataDiri[item].inputItem(bufferData);
        	//statField = dataDiri[item].inputItem(dataPadded);
       	 	statField = dataDiri[item].inputItem(dataStored);
            break;
        case indeksSTATIS:
        	//statField = dataStatis[item].inputItem(bufferData);
        	//statField = dataStatis[item].inputItem(dataPadded);
        	statField = dataStatis[item].inputItem(dataStored);
            break;
        case indeksDINAMIS:
        	//dataDinamis[stack].inputItem(item, bufferData);
       	 	//dataDinamis[stack].inputItem(item, dataPadded);
       	 	dataDinamis[stack].inputItem(item, dataStored);
            break;
        default:
        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    
    }
    private void deleteDataTEXT(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        
        byte numBytes =
            (byte)(buffer[ISO7816.OFFSET_LC]);
        
        byte byteRead =
            (byte)(apdu.setIncomingAndReceive());
        
        if ( ( numBytes != 0 ) || (byteRead != 0 ))
           ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        if (statField != 1){
      	  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
         }
        
        switch (type) {
        case indeksDATA:
       	 	statField = dataDiri[item].deleteItem();
            break;
        case indeksSTATIS:
        	statField = dataStatis[item].deleteItem();
            break;
        case indeksDINAMIS:
        	statField = dataDinamis[stack].deleteItem(item);
            break;
        default:
        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    
    }
    private void getDataTEXT(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	apdu.setOutgoing();
    	if(type != indeksDINAMIS){
	   		if (statField != 1){
	      	  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	         }	
   		}
   		
   		try{
   			switch (type) {
	        case indeksDATA:
	        	lenData = dataDiri[item].getLen();
	        	dataStored = dataDiri[item].getItem();
	            break;
	        case indeksSTATIS:
	        	lenData = dataStatis[item].getLen();
	        	dataStored = dataStatis[item].getItem();
	            break;
	        case indeksDINAMIS:
	       	 	byte numBytes = buffer[ISO7816.OFFSET_LC];
	       	 	
	        	if(numBytes !=  1){
	        		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        	}
	        	short stackRead = (short) buffer[ISO7816.OFFSET_LC+1];
	        	statField = dataDinamis[stackRead].getStat(item);
	        	
	        	if (statField != 1){
	  	      	  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	  	        }
	        	
	        	lenData = dataDinamis[stackRead].getLen(item);
	        	dataStored = dataDinamis[stackRead].getItem(item);
	            break;
	        default:
	        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
	        }
   		}catch (Exception e){
   			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
   		}
    	
        bufferData = doAesCipherFunction(Dec, lenData, dataStored);
//    	
    	byte[] data_final = removePadfromData(bufferData); //with chipper
//   		byte[] data_final = removePadfromData(dataStored); //no chiper
   		short len_final = (short) data_final.length;
//    	
//    	//no pad no chiper
//    	apdu.setOutgoingLength((short) lenData);
//    	Util.arrayCopyNonAtomic(dataStored ,(short) 0, buffer, (short) 0, lenData);
//    	apdu.sendBytes((short)0, (short) lenData);
    	//finale
    	apdu.setOutgoingLength((short) len_final);
    	Util.arrayCopyNonAtomic(data_final ,(short) 0, buffer, (short) 0, len_final);
    	apdu.sendBytes((short)0, (short) len_final);
    
    	
    }
//--//FUNGSI UTAMA DATA TEXT (CRUD)
    private void inputDataNUM(APDU apdu) {
   	 	byte[] buffer = apdu.getBuffer();
   	 	//Nilai LC dari APDU
        byte numBytes = buffer[ISO7816.OFFSET_LC]; //fix
        //Jumlah byte data
        short byteRead = apdu.setIncomingAndReceive();
        
        //Cek Kesesuaian LC-Jumlah Data dari APDU dan Ketersediaan field
        if ( ( numBytes != (byte) maxField ) || (byteRead != maxField) )
            ISOException.throwIt(SW_INVALID_DATA_INPUT_FIELD);
        
        if ( statField != (byte) 0 )
            ISOException.throwIt(SW_FIELD_NOT_EMPTY);
        
        //Input data dari APDU ke variabel modifikasi: dataNumProcess
        bufferData = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_RESET);
        short dataOffset;
        if ( numBytes == (byte) 1){
       	 	dataOffset = (short) 1;
        }else{
       	 	dataOffset = (short) 0;
        }
        
        while (byteRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, bufferData, dataOffset, byteRead);
            dataOffset += byteRead;
            byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
        //Sebelum data di input pada vriabel kelas
        //data dimasukan kedalam variabel sementara untuk pengecekan range
        short inputDATA = Util.getShort(bufferData, (short) 0);
        dataNumProcess = (short)(0 + inputDATA);
        
        // cek validitas range input data
        if ( ( inputDATA > maxVal)
             || ( inputDATA < minVal) )
            ISOException.throwIt(SW_INVALID_DATA_INPUT_RANGE);
        
        //cek apakah data kosong?
        if ( statField != (byte) 0 )
               ISOException.throwIt(SW_FIELD_NOT_EMPTY);
        
        //input data ke array yang bersesuaian
        short lenData = (short) bufferData.length;
        byte[] dataPadded;
        short len_dataPadded;
        
        dataPadded = addPadtoData(bufferData);
        len_dataPadded = (short) dataPadded.length;
        
        	
        dataStored = doAesCipherFunction(Enc, len_dataPadded, dataPadded);
        short len_dataFinal = (short) dataStored.length;
        
        switch (type) {
        case indeksDATA:
        	//statField = dataDiri[item].inputItem(bufferData);
        	//statField = dataDiri[item].inputItem(dataPadded);
       	 	statField = dataDiri[item].inputItem(dataStored);
            break;
        case indeksSTATIS:
        	//statField = dataStatis[item].inputItem(bufferData);
        	//statField = dataStatis[item].inputItem(dataPadded);
        	statField = dataStatis[item].inputItem(dataStored);
            break;
        case indeksDINAMIS:
        	//dataDinamis[stack].inputItem(item, bufferData);
       	 	//dataDinamis[stack].inputItem(item, dataPadded);
       	 	dataDinamis[stack].inputItem(item, dataStored);
            break;
        default:
        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    	
   }    
    private void deleteDataNUM(APDU apdu) {
       
       byte[] buffer = apdu.getBuffer();
       
       byte numBytes =
           (byte)(buffer[ISO7816.OFFSET_LC]);
       
       byte byteRead =
           (byte)(apdu.setIncomingAndReceive());
       
       if ( ( numBytes != 0 ) || (byteRead != 0 ))
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
       
       if (statField != 1){
    	  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
       }
       
       switch (type) {
       case indeksDATA:
      	 	statField = dataDiri[item].deleteItem();
      	 	break;
       case indeksSTATIS:
       		statField = dataStatis[item].deleteItem();
       		break;
       case indeksDINAMIS:
    	   	statField = dataDinamis[stack].deleteItem(item);
    	   	break;
       default:
       	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
       }
   }
    private void getDataNUM(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
   		apdu.setOutgoing();
   		
   		if(type != indeksDINAMIS){
	   		if (statField != 1){
	      	  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	         }	
   		}
   		
   		try{
   			switch (type) {
	        case indeksDATA:
	        	lenData = dataDiri[item].getLen();
	        	dataStored = dataDiri[item].getItem();
	            break;
	        case indeksSTATIS:
	        	lenData = dataStatis[item].getLen();
	        	dataStored = dataStatis[item].getItem();
	            break;
	        case indeksDINAMIS:
	       	 	byte numBytes = buffer[ISO7816.OFFSET_LC];
	       	 	
	        	if(numBytes !=  1){
	        		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        	}
	        	short stackRead = (short) buffer[ISO7816.OFFSET_LC+1];
	        	statField = dataDinamis[stackRead].getStat(item);
	        	
	        	if (statField != 1){
	  	      	  ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	  	        }
	        	
	        	lenData = dataDinamis[stackRead].getLen(item);
	        	dataStored = dataDinamis[stackRead].getItem(item);
	            break;
	        default:
	        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
	        }
   		}catch (Exception e){
   			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
   		}
   		short lenData = (short) dataStored.length;
    	
    	bufferData = doAesCipherFunction(Dec, lenData, dataStored);
//    	
   		
    	byte[] data_final = removePadfromData(bufferData); //with chipper
//   		byte[] data_final = removePadfromData(dataStored); //no chiper
   		short len_final = (short) data_final.length;
    	
    	//no pad no chiper
//    	dataNumProcess = Util.getShort(dataStored, (short) 0);
//    	Util.setShort(buffer, (short)0, dataNumProcess);
//    	apdu.sendBytes((short)0, (short) 2);
    	//with padding
//    	apdu.setOutgoingLength((short) lenData);
//    	Util.arrayCopyNonAtomic(dataStored ,(short) 0, buffer, (short) 0, lenData);
//    	apdu.sendBytes((short)0, (short) lenData);
//    	//finale
   		apdu.setOutgoingLength((byte) 2);
    	dataNumProcess = Util.getShort(data_final, (short) 0);
    	Util.setShort(buffer, (short)0, dataNumProcess);
    	apdu.sendBytes((short)0, (short) 2);
   }
//--//FUNGSI DATA DINAMIS
    private void registerDinamis(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();
        
        byte numBytes =
            (byte)(buffer[ISO7816.OFFSET_LC]);
        
        byte byteRead =
            (byte)(apdu.setIncomingAndReceive());
        
        if ( ( numBytes != 0 ) || (byteRead != 0 ))
           ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        switch (type) {
        case indeksDINAMIS:
        	for(short i=0; i<MAX_ITEM_DINAMIS; i++){
        		dataDinamis[stack].setStat((byte) i);
        	}
        	stack++;
            break;
        default:
        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    } 
    private void getStack(APDU apdu) {
	    
	    byte[] buffer = apdu.getBuffer();
	   
	    short le = apdu.setOutgoing();
	    
	    apdu.setOutgoingLength((byte)2);
	    
	    Util.setShort(buffer, (short)0, stack);
	    
	    apdu.sendBytes((short)0, (short)2);
	
	} 
//--//FUNGSI LAIN MANAGEMENT DATA (CRUD)
	private void getType(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();
        
        apdu.setOutgoingLength((byte)2);
            
        Util.setShort(buffer, (short)0, (short) type);
     
        apdu.sendBytes((short)0, (short)2);
    
    } // 
    private void getItem(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();
        
        apdu.setOutgoingLength((byte)2);

        Util.setShort(buffer, (short)0, (short) item);
        
        apdu.sendBytes((short)0, (short)2);
    
    } // 

    private void getLenDataStored(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();
        
        switch (type) {
        case indeksDATA:
        	lenData = dataDiri[item].getLen();
            break;
        case indeksSTATIS:
        	lenData = dataStatis[item].getLen();
            break;
        case indeksDINAMIS:
        	byte numBytes = buffer[ISO7816.OFFSET_LC];
        	if(numBytes !=  1){
        		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        	}
        	
        	byte stackRead = buffer[ISO7816.OFFSET_LC+1];
        	lenData = dataDinamis[stackRead].getLen(item);
            break;
        default:
        	ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength((byte)2);
        
        // 
        Util.setShort(buffer, (short)0, lenData);
        
        // send the 2-byte balance at the offset
        // 0 in the apdu buffer
        apdu.sendBytes((short)0, (short)2);
    
    } // 
    private void getField(APDU apdu) {
	    
	    byte[] buffer = apdu.getBuffer();
	    
	    short le = apdu.setOutgoing();
	    
	    apdu.setOutgoingLength((byte)2);
	      
	    Util.setShort(buffer, (short)0, buffer[ISO7816.OFFSET_LC]);
	    
	    apdu.sendBytes((short)0, (short)2);
	
	} 
    
    private void getMaxVal(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();
        short le = apdu.setOutgoing();

        apdu.setOutgoingLength((byte)2);
                
        Util.setShort(buffer, (short)0, maxVal);

        apdu.sendBytes((short)0, (short)2);
    
    } //
	private void getMinVal(APDU apdu) {    
		byte[] buffer = apdu.getBuffer();   
		short le = apdu.setOutgoing();
	        
		apdu.setOutgoingLength((byte)2);
	       
	   	Util.setShort(buffer, (short)0, minVal);
	        
	   	apdu.sendBytes((short)0, (short)2);
	    
	}
    private void getMaxField(APDU apdu) {
        
        byte[] buffer = apdu.getBuffer();
        
        short le = apdu.setOutgoing();

        apdu.setOutgoingLength((byte)2);
                
        Util.setShort(buffer, (short)0, maxField);

        apdu.sendBytes((short)0, (short)2);
    
    } //
	private void getMinField(APDU apdu) {
	        
	        byte[] buffer = apdu.getBuffer();
	        
	        short le = apdu.setOutgoing();
	        
	        apdu.setOutgoingLength((byte)2);
	       
	        Util.setShort(buffer, (short)0, minField);
	        
	        apdu.sendBytes((short)0, (short)2);
	    
	    } 
	
//--METODE KEAMANAN-----------------------------------------------------------------------//
//--//VERIFIKASI
	private void verifyUser(APDU apdu) {
	        byte[] buffer = apdu.getBuffer();
	        // retrieve the PIN data for validation.
	        byte byteRead = (byte)(apdu.setIncomingAndReceive());
	        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
	        
	        if (byteRead != numBytes){
	        	 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        }
	        // check pin
	        // the PIN data is read into the APDU buffer
	        // at the offset ISO7816.OFFSET_CDATA
	        // the PIN data length = byteRead
	        if ( pin.check(buffer, ISO7816.OFFSET_CDATA,
	            byteRead) == false )
	            ISOException.throwIt((short)(SW_VERIFICATION_FAILED + pin.getTriesRemaining()));
	        
	        
	    } // end of validate method
    private void verifyAdmin(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
        
        if (byteRead != numBytes){
        	 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if ( pinAdmin.check(buffer, ISO7816.OFFSET_CDATA,
            byteRead) == false )
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        
    }
    private void verifyDokter(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte)(apdu.setIncomingAndReceive());
        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
        
        if (byteRead != numBytes){
        	 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if ( pinDokter.check(buffer, ISO7816.OFFSET_CDATA,
            byteRead) == false )
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        
    }
    private void verifyOperator(APDU apdu){
	    	byte[] buffer = apdu.getBuffer();
	        // retrieve the PIN data for validation.
	        byte byteRead = (byte)(apdu.setIncomingAndReceive());
	        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
	        
	        if (byteRead != numBytes){
	        	 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        }
	        // check pin
	        // the PIN data is read into the APDU buffer
	        // at the offset ISO7816.OFFSET_CDATA
	        // the PIN data length = byteRead
	        if ( pinOperator.check(buffer, ISO7816.OFFSET_CDATA,
	            byteRead) == false )
	            ISOException.throwIt(SW_VERIFICATION_FAILED);
	        
	 }
//--//UPDATE PIN
    private void updatePin(APDU apdu){
    	if ( ! pinAdmin.isValidated() )
            ISOException.throwIt(SW_ADMIN_PIN_VERIFICATION_REQUIRED);
    	
    	byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.

        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
        short byteRead = apdu.setIncomingAndReceive();
        
        if ((short)numBytes != byteRead){
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      	}
        if (buffer[ISO7816.OFFSET_CDATA] < (byte) 0x02){
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        //masukin data
        bufferData = JCSystem.makeTransientByteArray((short) byteRead, JCSystem.CLEAR_ON_RESET);
       	short dataOffset = (short) 0;

        while (byteRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, bufferData, dataOffset, byteRead);
            dataOffset += byteRead;
            byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
        
        byte lenData = (byte) bufferData.length;
        
        JCSystem.beginTransaction();
        pin = new OwnerPIN(PIN_TRY_LIMIT_USER_USER,   MAX_PIN_SIZE_USER);
        pin.update(bufferData,(short)0,lenData);
        JCSystem.commitTransaction();

    }
    private void updatePinAdmin(APDU apdu){
    	if ( ! pinAdmin.isValidated() )
            ISOException.throwIt(SW_ADMIN_PIN_VERIFICATION_REQUIRED);
    	
    	byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.

        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
        short byteRead = apdu.setIncomingAndReceive();
        
        if ((short)numBytes != byteRead){
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      	}
        if (buffer[ISO7816.OFFSET_CDATA] < (byte) 0x02){
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        //masukin data
        bufferData = JCSystem.makeTransientByteArray((short) byteRead, JCSystem.CLEAR_ON_RESET);
       	short dataOffset = (short) 0;

        while (byteRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, bufferData, dataOffset, byteRead);
            dataOffset += byteRead;
            byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
        
        byte lenData = (byte) bufferData.length;
        if (lenData != (byte) 0x10){
        	ISOException.throwIt (ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        pinAdmin = new OwnerPIN(PIN_TRY_LIMIT_USER_ROLE,   MAX_PIN_SIZE_ROLE);
        pinAdmin.update(bufferData,(short)0,lenData);
        JCSystem.commitTransaction();

    }
    private void updatePinDokter(APDU apdu){
    	if ( ! pinAdmin.isValidated() )
            ISOException.throwIt(SW_ADMIN_PIN_VERIFICATION_REQUIRED);
    	
    	byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.

        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
        short byteRead = apdu.setIncomingAndReceive();
        
        if ((short)numBytes != byteRead){
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      	}
        if (buffer[ISO7816.OFFSET_CDATA] < (byte) 0x02){
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        //masukin data
        bufferData = JCSystem.makeTransientByteArray((short) byteRead, JCSystem.CLEAR_ON_RESET);
       	short dataOffset = (short) 0;

        while (byteRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, bufferData, dataOffset, byteRead);
            dataOffset += byteRead;
            byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
        
        byte lenData = (byte) bufferData.length;
        if (lenData != (byte) 0x10){
        	ISOException.throwIt (ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        pinDokter = new OwnerPIN(PIN_TRY_LIMIT_USER_ROLE,   MAX_PIN_SIZE_ROLE);
        pinDokter.update(bufferData,(short)0,lenData);
        JCSystem.commitTransaction();

    }
    private void updatePinOperator(APDU apdu){
    	if ( ! pinAdmin.isValidated() )
            ISOException.throwIt(SW_ADMIN_PIN_VERIFICATION_REQUIRED);
    	
    	byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.

        byte numBytes = buffer[ISO7816.OFFSET_LC]; 
        short byteRead = apdu.setIncomingAndReceive();
        
        if ((short)numBytes != byteRead){
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      	}
        if (buffer[ISO7816.OFFSET_CDATA] < (byte) 0x02){
        	ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
        
        //masukin data
        bufferData = JCSystem.makeTransientByteArray((short) byteRead, JCSystem.CLEAR_ON_RESET);
       	short dataOffset = (short) 0;

        while (byteRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, bufferData, dataOffset, byteRead);
            dataOffset += byteRead;
            byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
        
        byte lenData = (byte) bufferData.length;
        if (lenData != (byte) 0x10){
        	ISOException.throwIt (ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        pinOperator = new OwnerPIN(PIN_TRY_LIMIT_USER_ROLE,   MAX_PIN_SIZE_ROLE);
        pinOperator.update(bufferData,(short)0,lenData);
        JCSystem.commitTransaction();

    }

//--KRIPTOGRAFI-----------------------------------------------------------------------//
//--//GET KEY
    private Key getAesKey()
    {
    	if ( ! pin.isValidated() )
            ISOException.throwIt(SW_USER_PIN_VERIFICATION_REQUIRED);
    	
        Key tempAesKey = null;
        switch (aesKeyLen)
        {
        case (byte)32:
            tempAesKey = tempAesKey3;
            break;
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            break;
        }
        //Set the 'aesKey' key data value into the internal representation
        ((AESKey)tempAesKey).setKey(aesKey, (short)0);
        return tempAesKey;
    }
//--//DO CHIPER
    private byte[] doAesCipherFunction(byte processMode, short len, byte[] input)
    {
    	if ( !pin.isValidated() )
            ISOException.throwIt(SW_USER_PIN_VERIFICATION_REQUIRED);
        //The byte length to be encrypted/decrypted must be a multiple of 16
    	
    	byte[] output = new byte[len];
        if (len <= 0 || len % 16 != 0)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
 
        //byte[] buffer = apdu.getBuffer();
        Key key = getAesKey();
        byte mode = processMode == (byte)0x00 ? Cipher.MODE_ENCRYPT : Cipher.MODE_DECRYPT;
        Cipher cipher = aesCbcCipher;
        //Initializes the 'cipher' object with the appropriate Key and algorithm specific parameters.
        //AES algorithms in CBC mode expect a 16-byte parameter value for the initial vector(IV)
      
        cipher.init(key, mode, aesICV, (short)0, (short)16);
      
        //This method must be invoked to complete a cipher operation. Generates encrypted/decrypted output from all/last input data.
        cipher.doFinal(input, (short) 0, len, output, (short)0);
        
        return output;
    }
//--//PADDING DATA
    private byte[] addPadtoData(byte[] data){
    	
        short length =(short) data.length;
        
        
    	//get len padding yang dibutuhkan
        short len_padding;
        if(length < (short) 16){
        	len_padding = (short) (16 -length);
        }if(length == (short)16){
        	return data;
        }
    	else{
        	len_padding = (short) (16-(length % 16));
        }
    	
    	//panjang total
    	short len_dataPadded = (short) (len_padding+length);
    	byte[] data_padded = new byte[len_dataPadded];
    	//short val =(short) (len_padding+length);
      
     	
        //isi array dengan nol
        Util.arrayFillNonAtomic(data_padded, (short)0, len_dataPadded, (byte) 0x00);
        Util.arrayCopyNonAtomic(data,(short) 0, data_padded, (short) 0, length);
        Util.arrayFillNonAtomic(data_padded, length, (short) 1, (byte) 0x80);
        //Util.arrayCopyNonAtomic(data_padded,(short) 0, buffer, (short) 0, len_dataPadded);
        //Util.setShort(buffer, (short) 0,(short) val);

     	return data_padded;

    }   
    private byte[] removePadfromData(byte[] data){
    	
        short length =(short) data.length;
    	short len_final = length;
    	
    	if ( length == (short) 0 ) {
    		ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
    	}
    	
    	while ((length != (short) 0) && (data[(short)(length - 1)] == (byte)0x00)){
        	length = (short) (length-1);
        }
        
    	if (data[(short)(length-1)] != (byte)0x80 ) {
    		//ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    		return data;
    	}
    	
    	len_final = (short) (length - 1);
        byte[] data_noPad = new byte[len_final]; 
    	//byte[] data_final = new byte[len_final];

     	
     	Util.arrayCopyNonAtomic(data ,(short) 0, data_noPad, (short) 0, len_final);

     	return data_noPad;
    }
    private void getDataPadded(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
  	  
    	
    	short byteRead = apdu.setIncomingAndReceive();
    	byte numBytes = buffer[ISO7816.OFFSET_LC]; 
        
    	short dataOffset = (short) 0;
    	byte[] bufferData = new byte[byteRead];
    	
    	while (byteRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, bufferData, dataOffset, byteRead);
            dataOffset += byteRead;
            byteRead = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }
    	
        short length =(short) bufferData.length;
        
    	//get len padding yang dibutuhkan
        short len_padding;
    	if(length < (short) 16){
        	len_padding = (short) (16 -length);
        }if(length == (short) 16){
        	len_padding = (short)0;
        }else{
        	len_padding = (short) (16-(length % 16));
        }
    	
    	//panjang total
    	short len_dataPadded = (short) (len_padding+length);
    	byte[] data_padded = new byte[len_dataPadded];
    	//short val =(short) (len_padding+length);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) len_dataPadded);
     	
        //isi array dengan nol
        Util.arrayFillNonAtomic(data_padded, (short)0, len_dataPadded, (byte) 0x00);
        Util.arrayCopyNonAtomic(bufferData,(short) 0, data_padded, (short) 0, length);
        Util.arrayFillNonAtomic(data_padded, length, (short) 1, (byte) 0x80);
        Util.arrayCopyNonAtomic(data_padded,(short) 0, buffer, (short) 0, len_dataPadded);
        //Util.setShort(buffer, (short) 0,(short) val);

     	apdu.sendBytes((short)0, (short) len_dataPadded);
        //enkripsi
//        dataStored = doAesCipherFunction(Enc, len_dataPadded, dataPadded);
//        short len_dataFinal = (short) dataStored.length;
    
    }
//--DEKLRASI OBJEK DATA-----------------------------------------------------------------------//
//--//INISIASI PARAMETER
	public void InisiasiStatField(){
		Util.arrayFillNonAtomic(statField_DATA, (short) 0, MAX_ITEM_DATADIRI, (byte) 0);
    	Util.arrayFillNonAtomic(statField_STATIS, (short) 0, MAX_ITEM_STATIS, (byte) 0);
	}
    public void InisiasiMaxVal(){
        //DATA DIRI
        /* 6: Hubungan Keluarga                                                */ MAX_VAL_DATA[6] = (short) 7;
        /* 8: RT                                                               */ MAX_VAL_DATA[8] = (short) 30;
        /* 9: RW                                                               */ MAX_VAL_DATA[9] = (short) 30;
        /* 10: Kelurahan / Desa                                                */ MAX_VAL_DATA[10] = (short) 30;
        /* 11: Kecamatan                                                       */ MAX_VAL_DATA[11] = (short) 30;
        /* 12: Kota / Kabupaten                                                */ MAX_VAL_DATA[12] = (short) 30;
        /* 13: Propinsi                                                        */ MAX_VAL_DATA[13] = (short) 34;
        /* 15: Diluar/Didalam wilayah kerja                                    */ MAX_VAL_DATA[15] = (short) 2;
        /* 21: Jenis Kelamin                                                   */ MAX_VAL_DATA[21] = (short) 2;
        /* 22: Agama                                                           */ MAX_VAL_DATA[22] = (short) 6;
        /* 23: Pendidikan                                                      */ MAX_VAL_DATA[23] = (short) 7;
        /* 24: Pekerjaan                                                       */ MAX_VAL_DATA[24] = (short) 13;
        /* 27: Status perkawinan                                               */ MAX_VAL_DATA[27] = (short) 3;
        /* 28: Kewarganegaraan                                                 */ MAX_VAL_DATA[28] = (short) 2;
        /* 30: Hubungan                                                        */ MAX_VAL_DATA[30] = (short) 7;
        /* 32: Kelurahan / Desa                                                */ MAX_VAL_DATA[32] = (short) 30;
        /* 33: Kecamatan                                                       */ MAX_VAL_DATA[33] = (short) 30;
        /* 34: Kota / Kabupaten                                                */ MAX_VAL_DATA[34] = (short) 30;
        /* 35: Propinsi                                                        */ MAX_VAL_DATA[35] = (short) 34;
        /* 41: Kota / Kabupaten                                                */ MAX_VAL_DATA[41] = (short) 30;

        //REK. STATIS
        /* 1: Golongan darah                                                   */ MAX_VAL_STATIS[1] = (short) 8;

        //REK. DINAMIS
        /* 0: No Record (Index)                                                */ MAX_VAL_DINAMIS[0] = (short) 20;
        /* 7: Tinggi                                                           */ MAX_VAL_DINAMIS[7] = (short) 250;
        /* 8: Berat badan                                                      */ MAX_VAL_DINAMIS[8] = (short) 300;
        /* 9: Systole                                                          */ MAX_VAL_DINAMIS[9] = (short) 250;
        /* 10: Diastole                                                        */ MAX_VAL_DINAMIS[10] = (short) 250;
        /* 11: Nadi                                                            */ MAX_VAL_DINAMIS[11] = (short) 220;
        /* 12: Kesadaran                                                       */ MAX_VAL_DINAMIS[12] = (short) 6;
        /* 13: Suhu                                                            */ MAX_VAL_DINAMIS[13] = (short) 5000;
        /* 14: Respirasi                                                       */ MAX_VAL_DINAMIS[14] = (short) 60;
        /* 16: Lab execute flag                                                */ MAX_VAL_DINAMIS[16] = (short) 3;
        /* 22: Eksekusi resep flag                                             */ MAX_VAL_DINAMIS[22] = (short) 5;
        /* 23: Repetisi resep                                                  */ MAX_VAL_DINAMIS[23] = (short) 5;
        /* 24: Prognosa                                                        */ MAX_VAL_DINAMIS[24] = (short) 8;
        /* 35: Kode Penyakit ICD 1 Status Diagnosa                             */ MAX_VAL_DINAMIS[35] = (short) 100;
        /* 36: Kode Penyakit ICD 2 Status Diagnosa                             */ MAX_VAL_DINAMIS[36] = (short) 100;
        /* 37: Kode Penyakit ICD 3 Status Diagnosa                             */ MAX_VAL_DINAMIS[37] = (short) 100;
        /* 38: Kode Penyakit ICD 4 Status Diagnosa                             */ MAX_VAL_DINAMIS[38] = (short) 100;
        /* 39: Kode Penyakit ICD 5 Status Diagnosa                             */ MAX_VAL_DINAMIS[39] = (short) 100;
        /* 40: Kode Penyakit ICD 6 Status Diagnosa                             */ MAX_VAL_DINAMIS[40] = (short) 100;
        /* 41: Kode Penyakit ICD 7 Status Diagnosa                             */ MAX_VAL_DINAMIS[41] = (short) 100;
        /* 42: Kode Penyakit ICD 8 Status Diagnosa                             */ MAX_VAL_DINAMIS[42] = (short) 100;
        /* 43: Kode Penyakit ICD 9 Status Diagnosa                             */ MAX_VAL_DINAMIS[43] = (short) 100;
        /* 44: Kode Penyakit ICD 10 Status Diagnosa                            */ MAX_VAL_DINAMIS[44] = (short) 100;

	}
	public void InisiasiMinVal(){
		//MIN_VAL_<jenis tipe data>[item]
    	
	     //DATA DIRI
	     /* 6: Hubungan Keluarga                                                */ MIN_VAL_DATA[6] = (short) 1;
	     /* 8: RT                                                               */ MIN_VAL_DATA[8] = (short) 1;
	     /* 9: RW                                                               */ MIN_VAL_DATA[9] = (short) 1;
	     /* 10: Kelurahan / Desa                                                */ MIN_VAL_DATA[10] = (short) 1;
	     /* 11: Kecamatan                                                       */ MIN_VAL_DATA[11] = (short) 1;
	     /* 12: Kota / Kabupaten                                                */ MIN_VAL_DATA[12] = (short) 1;
	     /* 13: Propinsi                                                        */ MIN_VAL_DATA[13] = (short) 1;
	     /* 15: Diluar/Didalam wilayah kerja                                    */ MIN_VAL_DATA[15] = (short) 1;
	     /* 21: Jenis Kelamin                                                   */ MIN_VAL_DATA[21] = (short) 1;
	     /* 22: Agama                                                           */ MIN_VAL_DATA[22] = (short) 1;
	     /* 23: Pendidikan                                                      */ MIN_VAL_DATA[23] = (short) 1;
	     /* 24: Pekerjaan                                                       */ MIN_VAL_DATA[24] = (short) 1;
	     /* 27: Status perkawinan                                               */ MIN_VAL_DATA[27] = (short) 1;
	     /* 28: Kewarganegaraan                                                 */ MIN_VAL_DATA[28] = (short) 1;
	     /* 30: Hubungan                                                        */ MIN_VAL_DATA[30] = (short) 1;
	     /* 32: Kelurahan / Desa                                                */ MIN_VAL_DATA[32] = (short) 1;
	     /* 33: Kecamatan                                                       */ MIN_VAL_DATA[33] = (short) 1;
	     /* 34: Kota / Kabupaten                                                */ MIN_VAL_DATA[34] = (short) 1;
	     /* 35: Propinsi                                                        */ MIN_VAL_DATA[35] = (short) 1;
	     /* 41: Kota / Kabupaten                                                */ MIN_VAL_DATA[41] = (short) 1;

	     //REK. STATIS
	     /* 1: Golongan darah                                                   */ MIN_VAL_STATIS[1] = (short) 1;

	     //REK. DINAMIS
	     /* 0: No Record (Index)                                                */ MIN_VAL_DINAMIS[0] = (short) 1;
	     /* 7: Tinggi                                                           */ MIN_VAL_DINAMIS[7] = (short) 30;
	     /* 8: Berat badan                                                      */ MIN_VAL_DINAMIS[8] = (short) 10;
	     /* 9: Systole                                                          */ MIN_VAL_DINAMIS[9] = (short) 40;
	     /* 10: Diastole                                                        */ MIN_VAL_DINAMIS[10] = (short) 40;
	     /* 11: Nadi                                                            */ MIN_VAL_DINAMIS[11] = (short) 10;
	     /* 12: Kesadaran                                                       */ MIN_VAL_DINAMIS[12] = (short) 1;
	     /* 13: Suhu                                                            */ MIN_VAL_DINAMIS[13] = (short) 1200;
	     /* 14: Respirasi                                                       */ MIN_VAL_DINAMIS[14] = (short) 1;
	     /* 16: Lab execute flag                                                */ MIN_VAL_DINAMIS[16] = (short) 1;
	     /* 22: Eksekusi resep flag                                             */ MIN_VAL_DINAMIS[22] = (short) 1;
	     /* 23: Repetisi resep                                                  */ MIN_VAL_DINAMIS[23] = (short) 1;
	     /* 24: Prognosa                                                        */ MIN_VAL_DINAMIS[24] = (short) 1;
	     /* 35: Kode Penyakit ICD 1 Status Diagnosa                             */ MIN_VAL_DINAMIS[35] = (short) 1;
	     /* 36: Kode Penyakit ICD 2 Status Diagnosa                             */ MIN_VAL_DINAMIS[36] = (short) 1;
	     /* 37: Kode Penyakit ICD 3 Status Diagnosa                             */ MIN_VAL_DINAMIS[37] = (short) 1;
	     /* 38: Kode Penyakit ICD 4 Status Diagnosa                             */ MIN_VAL_DINAMIS[38] = (short) 1;
	     /* 39: Kode Penyakit ICD 5 Status Diagnosa                             */ MIN_VAL_DINAMIS[39] = (short) 1;
	     /* 40: Kode Penyakit ICD 6 Status Diagnosa                             */ MIN_VAL_DINAMIS[40] = (short) 1;
	     /* 41: Kode Penyakit ICD 7 Status Diagnosa                             */ MIN_VAL_DINAMIS[41] = (short) 1;
	     /* 42: Kode Penyakit ICD 8 Status Diagnosa                             */ MIN_VAL_DINAMIS[42] = (short) 1;
	     /* 43: Kode Penyakit ICD 9 Status Diagnosa                             */ MIN_VAL_DINAMIS[43] = (short) 1;
	     /* 44: Kode Penyakit ICD 10 Status Diagnosa                            */ MIN_VAL_DINAMIS[44] = (short) 1;

	}
    public void InisiasiMinField(){       	
    	//MIN_FIELD_<jenis tipe data>[indeks array item]
    	
        //DATA DIRI
        /* 0: No Smartcard                                                     */ MIN_FIELD_DATA[0] = (short) 3;
        /* 1: Kategori Pasien/Jenis pembayaran/Asuansi                         */ MIN_FIELD_DATA[1] = (short) 3;
        /* 2: Nomer Asuransi                                                   */ MIN_FIELD_DATA[2] = (short) 3;
        /* 3: Tanggal Daftar                                                   */ MIN_FIELD_DATA[3] = (short) 6;
        /* 4: Nama Pasien                                                      */ MIN_FIELD_DATA[4] = (short) 3;
        /* 5: Nama KK                                                          */ MIN_FIELD_DATA[5] = (short) 14;
        /* 6: Hubungan Keluarga                                                */ MIN_FIELD_DATA[6] = (short) 1;
        /* 7: Alamat                                                           */ MIN_FIELD_DATA[7] = (short) 3;
        /* 8: RT                                                               */ MIN_FIELD_DATA[8] = (short) 1;
        /* 9: RW                                                               */ MIN_FIELD_DATA[9] = (short) 1;
        /* 10: Kelurahan / Desa                                                */ MIN_FIELD_DATA[10] = (short) 1;
        /* 11: Kecamatan                                                       */ MIN_FIELD_DATA[11] = (short) 1;
        /* 12: Kota / Kabupaten                                                */ MIN_FIELD_DATA[12] = (short) 1;
        /* 13: Propinsi                                                        */ MIN_FIELD_DATA[13] = (short) 1;
        /* 14: Kode pos                                                        */ MIN_FIELD_DATA[14] = (short) 5;
        /* 15: Diluar/Didalam wilayah kerja                                    */ MIN_FIELD_DATA[15] = (short) 1;
        /* 16: Tempat Lahir                                                    */ MIN_FIELD_DATA[16] = (short) 3;
        /* 17: Tanggal Lahir                                                   */ MIN_FIELD_DATA[17] = (short) 6;
        /* 18: Telepon                                                         */ MIN_FIELD_DATA[18] = (short) 3;
        /* 19: HP                                                              */ MIN_FIELD_DATA[19] = (short) 3;
        /* 20: No. KTP (ID Number) - NIK                                       */ MIN_FIELD_DATA[20] = (short) 14;
        /* 21: Jenis Kelamin                                                   */ MIN_FIELD_DATA[21] = (short) 1;
        /* 22: Agama                                                           */ MIN_FIELD_DATA[22] = (short) 1;
        /* 23: Pendidikan                                                      */ MIN_FIELD_DATA[23] = (short) 1;
        /* 24: Pekerjaan                                                       */ MIN_FIELD_DATA[24] = (short) 1;
        /* 25: Kelas Perawatan                                                 */ MIN_FIELD_DATA[25] = (short) 3;
        /* 26: Alamat e-mail                                                   */ MIN_FIELD_DATA[26] = (short) 3;
        /* 27: Status perkawinan                                               */ MIN_FIELD_DATA[27] = (short) 1;
        /* 28: Kewarganegaraan                                                 */ MIN_FIELD_DATA[28] = (short) 1;
        /* 29: Nama Keluarga                                                   */ MIN_FIELD_DATA[29] = (short) 3;
        /* 30: Hubungan                                                        */ MIN_FIELD_DATA[30] = (short) 1;
        /* 31: Alamat                                                          */ MIN_FIELD_DATA[31] = (short) 3;
        /* 32: Kelurahan / Desa                                                */ MIN_FIELD_DATA[32] = (short) 1;
        /* 33: Kecamatan                                                       */ MIN_FIELD_DATA[33] = (short) 1;
        /* 34: Kota / Kabupaten                                                */ MIN_FIELD_DATA[34] = (short) 1;
        /* 35: Propinsi                                                        */ MIN_FIELD_DATA[35] = (short) 1;
        /* 36: Kode pos                                                        */ MIN_FIELD_DATA[36] = (short) 5;
        /* 37: Telepon                                                         */ MIN_FIELD_DATA[37] = (short) 3;
        /* 38: HP                                                              */ MIN_FIELD_DATA[38] = (short) 3;
        /* 39: Nama Kantor                                                     */ MIN_FIELD_DATA[39] = (short) 3;
        /* 40: Alamat Kantor                                                   */ MIN_FIELD_DATA[40] = (short) 3;
        /* 41: Kota / Kabupaten                                                */ MIN_FIELD_DATA[41] = (short) 1;
        /* 42: Telepon                                                         */ MIN_FIELD_DATA[42] = (short) 3;
        /* 43: HP                                                              */ MIN_FIELD_DATA[43] = (short) 3;
        /* 44: Telepon                                                         */ MIN_FIELD_DATA[44] = (short) 3;
        /* 45: HP                                                              */ MIN_FIELD_DATA[45] = (short) 3;

        //REK. STATIS
        /* 0: Alergi                                                           */ MIN_FIELD_STATIS[0] = (short) 3;
        /* 1: Golongan darah                                                   */ MIN_FIELD_STATIS[1] = (short) 1;
        /* 2: Riwayat Operasi                                                  */ MIN_FIELD_STATIS[2] = (short) 3;
        /* 3: Riwayat Rawat RS                                                 */ MIN_FIELD_STATIS[3] = (short) 3;
        /* 4: Riwayat penyakit Kronis (Jantung, Paru, Ginjal, dll.)            */ MIN_FIELD_STATIS[4] = (short) 3;
        /* 5: Riwayat penyakit bawaan dan orang tua/keluarga/kerabat           */ MIN_FIELD_STATIS[5] = (short) 3;
        /* 6: Faktor Resiko                                                    */ MIN_FIELD_STATIS[6] = (short) 3;

        //REK. DINAMIS
        /* 0: No Record (Index)                                                */ MIN_FIELD_DINAMIS[0] = (short) 1;
        /* 1: Tanggal periksa                                                  */ MIN_FIELD_DINAMIS[1] = (short) 6;
        /* 2: Keluhan utama                                                    */ MIN_FIELD_DINAMIS[2] = (short) 3;
        /* 3: Anamnesa                                                         */ MIN_FIELD_DINAMIS[3] = (short) 3;
        /* 4: Riwayat Penyakit Dahulu                                          */ MIN_FIELD_DINAMIS[4] = (short) 3;
        /* 5: Riwayat Penyakit pada keluarga/kerabat                           */ MIN_FIELD_DINAMIS[5] = (short) 3;
        /* 6: Pemeriksaan Fisik                                                */ MIN_FIELD_DINAMIS[6] = (short) 3;
        /* 7: Tinggi                                                           */ MIN_FIELD_DINAMIS[7] = (short) 1;
        /* 8: Berat badan                                                      */ MIN_FIELD_DINAMIS[8] = (short) 1;
        /* 9: Systole                                                          */ MIN_FIELD_DINAMIS[9] = (short) 1;
        /* 10: Diastole                                                        */ MIN_FIELD_DINAMIS[10] = (short) 1;
        /* 11: Nadi                                                            */ MIN_FIELD_DINAMIS[11] = (short) 1;
        /* 12: Kesadaran                                                       */ MIN_FIELD_DINAMIS[12] = (short) 1;
        /* 13: Suhu                                                            */ MIN_FIELD_DINAMIS[13] = (short) 2;
        /* 14: Respirasi                                                       */ MIN_FIELD_DINAMIS[14] = (short) 1;
        /* 15: Lain-lain                                                       */ MIN_FIELD_DINAMIS[15] = (short) 3;
        /* 16: Lab execute flag                                                */ MIN_FIELD_DINAMIS[16] = (short) 1;
        /* 17: Expertise Lab/Radio/etc                                         */ MIN_FIELD_DINAMIS[17] = (short) 3;
        /* 18: Catatan Lab                                                     */ MIN_FIELD_DINAMIS[18] = (short) 3;
        /* 19: Terapi                                                          */ MIN_FIELD_DINAMIS[19] = (short) 3;
        /* 20: Resep                                                           */ MIN_FIELD_DINAMIS[20] = (short) 3;
        /* 21: Catatan resep                                                   */ MIN_FIELD_DINAMIS[21] = (short) 3;
        /* 22: Eksekusi resep flag                                             */ MIN_FIELD_DINAMIS[22] = (short) 1;
        /* 23: Repetisi resep                                                  */ MIN_FIELD_DINAMIS[23] = (short) 1;
        /* 24: Prognosa                                                        */ MIN_FIELD_DINAMIS[24] = (short) 1;
        /* 25: Kode Penyakit ICD 1                                             */ MIN_FIELD_DINAMIS[25] = (short) 3;
        /* 26: Kode Penyakit ICD 2                                             */ MIN_FIELD_DINAMIS[26] = (short) 3;
        /* 27: Kode Penyakit ICD 3                                             */ MIN_FIELD_DINAMIS[27] = (short) 3;
        /* 28: Kode Penyakit ICD 4                                             */ MIN_FIELD_DINAMIS[28] = (short) 3;
        /* 29: Kode Penyakit ICD 5                                             */ MIN_FIELD_DINAMIS[29] = (short) 3;
        /* 30: Kode Penyakit ICD 6                                             */ MIN_FIELD_DINAMIS[30] = (short) 3;
        /* 31: Kode Penyakit ICD 7                                             */ MIN_FIELD_DINAMIS[31] = (short) 3;
        /* 32: Kode Penyakit ICD 8                                             */ MIN_FIELD_DINAMIS[32] = (short) 3;
        /* 33: Kode Penyakit ICD 9                                             */ MIN_FIELD_DINAMIS[33] = (short) 3;
        /* 34: Kode Penyakit ICD 10                                            */ MIN_FIELD_DINAMIS[34] = (short) 3;
        /* 35: Kode Penyakit ICD 1 Status Diagnosa                             */ MIN_FIELD_DINAMIS[35] = (short) 1;
        /* 36: Kode Penyakit ICD 2 Status Diagnosa                             */ MIN_FIELD_DINAMIS[36] = (short) 1;
        /* 37: Kode Penyakit ICD 3 Status Diagnosa                             */ MIN_FIELD_DINAMIS[37] = (short) 1;
        /* 38: Kode Penyakit ICD 4 Status Diagnosa                             */ MIN_FIELD_DINAMIS[38] = (short) 1;
        /* 39: Kode Penyakit ICD 5 Status Diagnosa                             */ MIN_FIELD_DINAMIS[39] = (short) 1;
        /* 40: Kode Penyakit ICD 6 Status Diagnosa                             */ MIN_FIELD_DINAMIS[40] = (short) 1;
        /* 41: Kode Penyakit ICD 7 Status Diagnosa                             */ MIN_FIELD_DINAMIS[41] = (short) 1;
        /* 42: Kode Penyakit ICD 8 Status Diagnosa                             */ MIN_FIELD_DINAMIS[42] = (short) 1;
        /* 43: Kode Penyakit ICD 9 Status Diagnosa                             */ MIN_FIELD_DINAMIS[43] = (short) 1;
        /* 44: Kode Penyakit ICD 10 Status Diagnosa                            */ MIN_FIELD_DINAMIS[44] = (short) 1;
        /* 45: Poli yang dituju                                                */ MIN_FIELD_DINAMIS[45] = (short) 3;
        /* 46: Rujukan/Pengirim penderita                                      */ MIN_FIELD_DINAMIS[46] = (short) 3;
        /* 47: ID Puskesmas                                                    */ MIN_FIELD_DINAMIS[47] = (short) 3;

    }
    public void InisiasiMaxField(){
    	//MAX_FIELD_<jenis tipe data>[item]
    	
    	//DATA DIRI
        /* 0: No Smartcard                                                     */ MAX_FIELD_DATA[0] = (short) 20;
        /* 1: Kategori Pasien/Jenis pembayaran/Asuansi                         */ MAX_FIELD_DATA[1] = (short) 12;
        /* 2: Nomer Asuransi                                                   */ MAX_FIELD_DATA[2] = (short) 20;
        /* 3: Tanggal Daftar                                                   */ MAX_FIELD_DATA[3] = (short) 6;
        /* 4: Nama Pasien                                                      */ MAX_FIELD_DATA[4] = (short) 50;
        /* 5: Nama KK                                                          */ MAX_FIELD_DATA[5] = (short) 32;
        /* 6: Hubungan Keluarga                                                */ MAX_FIELD_DATA[6] = (short) 1;
        /* 7: Alamat                                                           */ MAX_FIELD_DATA[7] = (short) 50;
        /* 8: RT                                                               */ MAX_FIELD_DATA[8] = (short) 1;
        /* 9: RW                                                               */ MAX_FIELD_DATA[9] = (short) 1;
        /* 10: Kelurahan / Desa                                                */ MAX_FIELD_DATA[10] = (short) 1;
        /* 11: Kecamatan                                                       */ MAX_FIELD_DATA[11] = (short) 1;
        /* 12: Kota / Kabupaten                                                */ MAX_FIELD_DATA[12] = (short) 1;
        /* 13: Propinsi                                                        */ MAX_FIELD_DATA[13] = (short) 1;
        /* 14: Kode pos                                                        */ MAX_FIELD_DATA[14] = (short) 5;
        /* 15: Diluar/Didalam wilayah kerja                                    */ MAX_FIELD_DATA[15] = (short) 1;
        /* 16: Tempat Lahir                                                    */ MAX_FIELD_DATA[16] = (short) 10;
        /* 17: Tanggal Lahir                                                   */ MAX_FIELD_DATA[17] = (short) 6;
        /* 18: Telepon                                                         */ MAX_FIELD_DATA[18] = (short) 12;
        /* 19: HP                                                              */ MAX_FIELD_DATA[19] = (short) 12;
        /* 20: No. KTP (ID Number) - NIK                                       */ MAX_FIELD_DATA[20] = (short) 32;
        /* 21: Jenis Kelamin                                                   */ MAX_FIELD_DATA[21] = (short) 1;
        /* 22: Agama                                                           */ MAX_FIELD_DATA[22] = (short) 1;
        /* 23: Pendidikan                                                      */ MAX_FIELD_DATA[23] = (short) 1;
        /* 24: Pekerjaan                                                       */ MAX_FIELD_DATA[24] = (short) 1;
        /* 25: Kelas Perawatan                                                 */ MAX_FIELD_DATA[25] = (short) 12;
        /* 26: Alamat e-mail                                                   */ MAX_FIELD_DATA[26] = (short) 30;
        /* 27: Status perkawinan                                               */ MAX_FIELD_DATA[27] = (short) 1;
        /* 28: Kewarganegaraan                                                 */ MAX_FIELD_DATA[28] = (short) 1;
        /* 29: Nama Keluarga                                                   */ MAX_FIELD_DATA[29] = (short) 50;
        /* 30: Hubungan                                                        */ MAX_FIELD_DATA[30] = (short) 1;
        /* 31: Alamat                                                          */ MAX_FIELD_DATA[31] = (short) 50;
        /* 32: Kelurahan / Desa                                                */ MAX_FIELD_DATA[32] = (short) 1;
        /* 33: Kecamatan                                                       */ MAX_FIELD_DATA[33] = (short) 1;
        /* 34: Kota / Kabupaten                                                */ MAX_FIELD_DATA[34] = (short) 1;
        /* 35: Propinsi                                                        */ MAX_FIELD_DATA[35] = (short) 1;
        /* 36: Kode pos                                                        */ MAX_FIELD_DATA[36] = (short) 5;
        /* 37: Telepon                                                         */ MAX_FIELD_DATA[37] = (short) 12;
        /* 38: HP                                                              */ MAX_FIELD_DATA[38] = (short) 12;
        /* 39: Nama Kantor                                                     */ MAX_FIELD_DATA[39] = (short) 20;
        /* 40: Alamat Kantor                                                   */ MAX_FIELD_DATA[40] = (short) 30;
        /* 41: Kota / Kabupaten                                                */ MAX_FIELD_DATA[41] = (short) 1;
        /* 42: Telepon                                                         */ MAX_FIELD_DATA[42] = (short) 12;
        /* 43: HP                                                              */ MAX_FIELD_DATA[43] = (short) 12;
        /* 44: Telepon                                                         */ MAX_FIELD_DATA[44] = (short) 12;
        /* 45: HP                                                              */ MAX_FIELD_DATA[45] = (short) 12;

        //REK. STATIS
        /* 0: Alergi                                                           */ MAX_FIELD_STATIS[0] = (short) 100;
        /* 1: Golongan darah                                                   */ MAX_FIELD_STATIS[1] = (short) 1;
        /* 2: Riwayat Operasi                                                  */ MAX_FIELD_STATIS[2] = (short) 255;
        /* 3: Riwayat Rawat RS                                                 */ MAX_FIELD_STATIS[3] = (short) 255;
        /* 4: Riwayat penyakit Kronis (Jantung, Paru, Ginjal, dll.)            */ MAX_FIELD_STATIS[4] = (short) 255;
        /* 5: Riwayat penyakit bawaan dan orang tua/keluarga/kerabat           */ MAX_FIELD_STATIS[5] = (short) 255;
        /* 6: Faktor Resiko                                                    */ MAX_FIELD_STATIS[6] = (short) 255;

        //REK. DINAMIS
        /* 0: No Record (Index)                                                */ MAX_FIELD_DINAMIS[0] = (short) 1;
        /* 1: Tanggal periksa                                                  */ MAX_FIELD_DINAMIS[1] = (short) 6;
        /* 2: Keluhan utama                                                    */ MAX_FIELD_DINAMIS[2] = (short) 50;
        /* 3: Anamnesa                                                         */ MAX_FIELD_DINAMIS[3] = (short) 200;
        /* 4: Riwayat Penyakit Dahulu                                          */ MAX_FIELD_DINAMIS[4] = (short) 100;
        /* 5: Riwayat Penyakit pada keluarga/kerabat                           */ MAX_FIELD_DINAMIS[5] = (short) 100;
        /* 6: Pemeriksaan Fisik                                                */ MAX_FIELD_DINAMIS[6] = (short) 100;
        /* 7: Tinggi                                                           */ MAX_FIELD_DINAMIS[7] = (short) 1;
        /* 8: Berat badan                                                      */ MAX_FIELD_DINAMIS[8] = (short) 1;
        /* 9: Systole                                                          */ MAX_FIELD_DINAMIS[9] = (short) 1;
        /* 10: Diastole                                                        */ MAX_FIELD_DINAMIS[10] = (short) 1;
        /* 11: Nadi                                                            */ MAX_FIELD_DINAMIS[11] = (short) 1;
        /* 12: Kesadaran                                                       */ MAX_FIELD_DINAMIS[12] = (short) 1;
        /* 13: Suhu                                                            */ MAX_FIELD_DINAMIS[13] = (short) 2;
        /* 14: Respirasi                                                       */ MAX_FIELD_DINAMIS[14] = (short) 1;
        /* 15: Lain-lain                                                       */ MAX_FIELD_DINAMIS[15] = (short) 250;
        /* 16: Lab execute flag                                                */ MAX_FIELD_DINAMIS[16] = (short) 1;
        /* 17: Expertise Lab/Radio/etc                                         */ MAX_FIELD_DINAMIS[17] = (short) 512;
        /* 18: Catatan Lab                                                     */ MAX_FIELD_DINAMIS[18] = (short) 50;
        /* 19: Terapi                                                          */ MAX_FIELD_DINAMIS[19] = (short) 512;
        /* 20: Resep                                                           */ MAX_FIELD_DINAMIS[20] = (short) 200;
        /* 21: Catatan resep                                                   */ MAX_FIELD_DINAMIS[21] = (short) 50;
        /* 22: Eksekusi resep flag                                             */ MAX_FIELD_DINAMIS[22] = (short) 1;
        /* 23: Repetisi resep                                                  */ MAX_FIELD_DINAMIS[23] = (short) 1;
        /* 24: Prognosa                                                        */ MAX_FIELD_DINAMIS[24] = (short) 1;
        /* 25: Kode Penyakit ICD 1                                             */ MAX_FIELD_DINAMIS[25] = (short) 20;
        /* 26: Kode Penyakit ICD 2                                             */ MAX_FIELD_DINAMIS[26] = (short) 20;
        /* 27: Kode Penyakit ICD 3                                             */ MAX_FIELD_DINAMIS[27] = (short) 20;
        /* 28: Kode Penyakit ICD 4                                             */ MAX_FIELD_DINAMIS[28] = (short) 20;
        /* 29: Kode Penyakit ICD 5                                             */ MAX_FIELD_DINAMIS[29] = (short) 20;
        /* 30: Kode Penyakit ICD 6                                             */ MAX_FIELD_DINAMIS[30] = (short) 20;
        /* 31: Kode Penyakit ICD 7                                             */ MAX_FIELD_DINAMIS[31] = (short) 20;
        /* 32: Kode Penyakit ICD 8                                             */ MAX_FIELD_DINAMIS[32] = (short) 20;
        /* 33: Kode Penyakit ICD 9                                             */ MAX_FIELD_DINAMIS[33] = (short) 20;
        /* 34: Kode Penyakit ICD 10                                            */ MAX_FIELD_DINAMIS[34] = (short) 20;
        /* 35: Kode Penyakit ICD 1 Status Diagnosa                             */ MAX_FIELD_DINAMIS[35] = (short) 1;
        /* 36: Kode Penyakit ICD 2 Status Diagnosa                             */ MAX_FIELD_DINAMIS[36] = (short) 1;
        /* 37: Kode Penyakit ICD 3 Status Diagnosa                             */ MAX_FIELD_DINAMIS[37] = (short) 1;
        /* 38: Kode Penyakit ICD 4 Status Diagnosa                             */ MAX_FIELD_DINAMIS[38] = (short) 1;
        /* 39: Kode Penyakit ICD 5 Status Diagnosa                             */ MAX_FIELD_DINAMIS[39] = (short) 1;
        /* 40: Kode Penyakit ICD 6 Status Diagnosa                             */ MAX_FIELD_DINAMIS[40] = (short) 1;
        /* 41: Kode Penyakit ICD 7 Status Diagnosa                             */ MAX_FIELD_DINAMIS[41] = (short) 1;
        /* 42: Kode Penyakit ICD 8 Status Diagnosa                             */ MAX_FIELD_DINAMIS[42] = (short) 1;
        /* 43: Kode Penyakit ICD 9 Status Diagnosa                             */ MAX_FIELD_DINAMIS[43] = (short) 1;
        /* 44: Kode Penyakit ICD 10 Status Diagnosa                            */ MAX_FIELD_DINAMIS[44] = (short) 1;
        /* 45: Poli yang dituju                                                */ MAX_FIELD_DINAMIS[45] = (short) 50;
        /* 46: Rujukan/Pengirim penderita                                      */ MAX_FIELD_DINAMIS[46] = (short) 30;
        /* 47: ID Puskesmas                                                    */ MAX_FIELD_DINAMIS[47] = (short) 12;


    }
//--//LEN DATA DENGAN PAD
    public static short LenPadded(short maxField){
    	short lenPad;
    	
    	short div = (short) (maxField/16);
    	short mod = (short) (maxField%16);
    	
    	if (mod!= (short) 0){
    		lenPad = (short) (16*(div+1));
    	}else{
    		lenPad = (short) (16*div);
    	}
    	
    	return lenPad;
    }
//--//INISIASI DATA
    public void InisiasiDataTEXT(){
    //--//DATA DIRI
    	 //--//DATA DIRI 
    	 dataDiri = new IsiDataTEXT[MAX_ITEM_DATADIRI];
    	 dataDiri[0] = new IsiDataTEXT();
    	 dataDiri[0].setData(LenPadded(MAX_FIELD_DATA[0]));
    	 dataDiri[1] = new IsiDataTEXT();
    	 dataDiri[1].setData(LenPadded(MAX_FIELD_DATA[1]));
    	 dataDiri[2] = new IsiDataTEXT();
    	 dataDiri[2].setData(LenPadded(MAX_FIELD_DATA[2]));
    	 dataDiri[3] = new IsiDataTEXT();
    	 dataDiri[3].setData(LenPadded(MAX_FIELD_DATA[3]));
    	 dataDiri[4] = new IsiDataTEXT();
    	 dataDiri[4].setData(LenPadded(MAX_FIELD_DATA[4]));
    	 dataDiri[5] = new IsiDataTEXT();
    	 dataDiri[5].setData(LenPadded(MAX_FIELD_DATA[5]));
    	 dataDiri[6] = new IsiDataTEXT();
    	 dataDiri[6].setData(LenPadded(MAX_FIELD_DATA[6]));
    	 dataDiri[7] = new IsiDataTEXT();
    	 dataDiri[7].setData(LenPadded(MAX_FIELD_DATA[7]));
    	 dataDiri[8] = new IsiDataTEXT();
    	 dataDiri[8].setData(LenPadded(MAX_FIELD_DATA[8]));
    	 dataDiri[9] = new IsiDataTEXT();
    	 dataDiri[9].setData(LenPadded(MAX_FIELD_DATA[9]));
    	 dataDiri[10] = new IsiDataTEXT();
    	 dataDiri[10].setData(LenPadded(MAX_FIELD_DATA[10]));
    	 dataDiri[11] = new IsiDataTEXT();
    	 dataDiri[11].setData(LenPadded(MAX_FIELD_DATA[11]));
    	 dataDiri[12] = new IsiDataTEXT();
    	 dataDiri[12].setData(LenPadded(MAX_FIELD_DATA[12]));
    	 dataDiri[13] = new IsiDataTEXT();
    	 dataDiri[13].setData(LenPadded(MAX_FIELD_DATA[13]));
    	 dataDiri[14] = new IsiDataTEXT();
    	 dataDiri[14].setData(LenPadded(MAX_FIELD_DATA[14]));
    	 dataDiri[15] = new IsiDataTEXT();
    	 dataDiri[15].setData(LenPadded(MAX_FIELD_DATA[15]));
    	 dataDiri[16] = new IsiDataTEXT();
    	 dataDiri[16].setData(LenPadded(MAX_FIELD_DATA[16]));
    	 dataDiri[17] = new IsiDataTEXT();
    	 dataDiri[17].setData(LenPadded(MAX_FIELD_DATA[17]));
    	 dataDiri[18] = new IsiDataTEXT();
    	 dataDiri[18].setData(LenPadded(MAX_FIELD_DATA[18]));
    	 dataDiri[19] = new IsiDataTEXT();
    	 dataDiri[19].setData(LenPadded(MAX_FIELD_DATA[19]));
    	 dataDiri[20] = new IsiDataTEXT();
    	 dataDiri[20].setData(LenPadded(MAX_FIELD_DATA[20]));
    	 dataDiri[21] = new IsiDataTEXT();
    	 dataDiri[21].setData(LenPadded(MAX_FIELD_DATA[21]));
    	 dataDiri[22] = new IsiDataTEXT();
    	 dataDiri[22].setData(LenPadded(MAX_FIELD_DATA[22]));
    	 dataDiri[23] = new IsiDataTEXT();
    	 dataDiri[23].setData(LenPadded(MAX_FIELD_DATA[23]));
    	 dataDiri[24] = new IsiDataTEXT();
    	 dataDiri[24].setData(LenPadded(MAX_FIELD_DATA[24]));
    	 dataDiri[25] = new IsiDataTEXT();
    	 dataDiri[25].setData(LenPadded(MAX_FIELD_DATA[25]));
    	 dataDiri[26] = new IsiDataTEXT();
    	 dataDiri[26].setData(LenPadded(MAX_FIELD_DATA[26]));
    	 dataDiri[27] = new IsiDataTEXT();
    	 dataDiri[27].setData(LenPadded(MAX_FIELD_DATA[27]));
    	 dataDiri[28] = new IsiDataTEXT();
    	 dataDiri[28].setData(LenPadded(MAX_FIELD_DATA[28]));
    	 dataDiri[29] = new IsiDataTEXT();
    	 dataDiri[29].setData(LenPadded(MAX_FIELD_DATA[29]));
    	 dataDiri[30] = new IsiDataTEXT();
    	 dataDiri[30].setData(LenPadded(MAX_FIELD_DATA[30]));
    	 dataDiri[31] = new IsiDataTEXT();
    	 dataDiri[31].setData(LenPadded(MAX_FIELD_DATA[31]));
    	 dataDiri[32] = new IsiDataTEXT();
    	 dataDiri[32].setData(LenPadded(MAX_FIELD_DATA[32]));
    	 dataDiri[33] = new IsiDataTEXT();
    	 dataDiri[33].setData(LenPadded(MAX_FIELD_DATA[33]));
    	 dataDiri[34] = new IsiDataTEXT();
    	 dataDiri[34].setData(LenPadded(MAX_FIELD_DATA[34]));
    	 dataDiri[35] = new IsiDataTEXT();
    	 dataDiri[35].setData(LenPadded(MAX_FIELD_DATA[35]));
    	 dataDiri[36] = new IsiDataTEXT();
    	 dataDiri[36].setData(LenPadded(MAX_FIELD_DATA[36]));
    	 dataDiri[37] = new IsiDataTEXT();
    	 dataDiri[37].setData(LenPadded(MAX_FIELD_DATA[37]));
    	 dataDiri[38] = new IsiDataTEXT();
    	 dataDiri[38].setData(LenPadded(MAX_FIELD_DATA[38]));
    	 dataDiri[39] = new IsiDataTEXT();
    	 dataDiri[39].setData(LenPadded(MAX_FIELD_DATA[39]));
    	 dataDiri[40] = new IsiDataTEXT();
    	 dataDiri[40].setData(LenPadded(MAX_FIELD_DATA[40]));
    	 dataDiri[41] = new IsiDataTEXT();
    	 dataDiri[41].setData(LenPadded(MAX_FIELD_DATA[41]));
    	 dataDiri[42] = new IsiDataTEXT();
    	 dataDiri[42].setData(LenPadded(MAX_FIELD_DATA[42]));
    	 dataDiri[43] = new IsiDataTEXT();
    	 dataDiri[43].setData(LenPadded(MAX_FIELD_DATA[43]));
    //--//DATA STATIS
    	dataStatis = new IsiDataTEXT[MAX_ITEM_STATIS];
    	
    	for(short i=0; i<MAX_ITEM_STATIS; i++){
    		dataStatis[i] = new IsiDataTEXT();
    		dataStatis[i].setData(LenPadded(MAX_FIELD_STATIS[i]));
    	}
    //--//DINAMIS
		dataDinamis = new ItemDinamisTEXT[MAX_STACK];
		
		dataDinamis[0] = new ItemDinamisTEXT();
    	dataDinamis[1] = new ItemDinamisTEXT();
    	dataDinamis[2] = new ItemDinamisTEXT();
    	dataDinamis[3] = new ItemDinamisTEXT();
    	dataDinamis[4] = new ItemDinamisTEXT();
    	dataDinamis[5] = new ItemDinamisTEXT();
    	dataDinamis[6] = new ItemDinamisTEXT();
    	dataDinamis[7] = new ItemDinamisTEXT();
    	dataDinamis[8] = new ItemDinamisTEXT();
    	dataDinamis[9] = new ItemDinamisTEXT();
    	dataDinamis[10] = new ItemDinamisTEXT();
    	dataDinamis[11] = new ItemDinamisTEXT();
    	dataDinamis[12] = new ItemDinamisTEXT();
    	dataDinamis[13] = new ItemDinamisTEXT();
    	dataDinamis[14] = new ItemDinamisTEXT();
    	dataDinamis[15] = new ItemDinamisTEXT();
    	dataDinamis[16] = new ItemDinamisTEXT();
    	dataDinamis[17] = new ItemDinamisTEXT();
    	dataDinamis[18] = new ItemDinamisTEXT();
    	dataDinamis[19] = new ItemDinamisTEXT();
    	
    	dataDinamis[0].setData();
		dataDinamis[1].setData();
		dataDinamis[2].setData();
		dataDinamis[3].setData();
		dataDinamis[4].setData();
		dataDinamis[5].setData();
		dataDinamis[6].setData();
		dataDinamis[7].setData();
		dataDinamis[8].setData();
		dataDinamis[9].setData();
		dataDinamis[10].setData();
		dataDinamis[11].setData();
		dataDinamis[12].setData();
		dataDinamis[13].setData();
		dataDinamis[14].setData();
		dataDinamis[15].setData();
		dataDinamis[16].setData();
		dataDinamis[17].setData();
		dataDinamis[18].setData();
		dataDinamis[19].setData();
    }	

//--//OBJEK DATA
//--//OBJEK DATA    
    class ItemDinamisTEXT{
    	public IsiDataTEXT[] itemDinamis;
    	
    	private byte[] maxFieldDinamis = new byte[48];
    	
    	public void setData(){
    		itemDinamis = new IsiDataTEXT[MAX_ITEM_DINAMIS];
    		for(short i=0; i<MAX_ITEM_DINAMIS; i++){
        		itemDinamis[i] = new IsiDataTEXT();
        		itemDinamis[i].setData(LenPadded(maxFieldDinamis[i]));
    		}
//    		itemDinamis[13] = new IsiDataTEXT();
//    		itemDinamis[13].setData(LenPadded(maxFieldDinamis[13]));
//    		
//    		itemDinamis[25] = new IsiDataTEXT();
//    		itemDinamis[25].setData(LenPadded(maxFieldDinamis[25]));
//    		
//    		itemDinamis[47] = new IsiDataTEXT();
//    		itemDinamis[47].setData(LenPadded(maxFieldDinamis[47]));
    		
    	}
    	public void inputItem(byte Item, byte[] inputVal){
    		itemDinamis[Item].inputItem(inputVal);
    	}
    	public byte[] getItem(byte Item){
    		return itemDinamis[Item].getItem();
    	}
    	public byte deleteItem(byte Item){
    		return itemDinamis[Item].deleteItem();
    	}
    	public short getLen(byte Item){
    		return itemDinamis[Item].getLen();
    	}
    	public byte getStat(byte Item){
    		return itemDinamis[Item].getStat();
    	}
    	public void setStat(byte Item){
    		itemDinamis[Item].statField = 1;
    	}
    }
    class IsiDataTEXT{
    	public byte[] isiData; 
    	public byte statField; 
    	public short lenData;
    	public void setData(short maxField){
    		//isiData = new byte[maxField];
    		//isiData = null;
    		statField = 0;
    	}
    	public byte inputItem(byte[] inputVal){
    		lenData = (short) inputVal.length;
    		isiData = new byte[lenData];
    		Util.arrayCopyNonAtomic(inputVal,(short) 0, isiData, (short) 0, lenData);
    		statField = 1;
    		return statField;
    	}
    	public byte[] getItem(){
    		return isiData;
    	}
    	public byte deleteItem(){
    		isiData = new byte[]{};
    		//isiData = null;
    		statField = 0;
    		return statField;
    	}
    	public short getLen(){
    		lenData = (short) isiData.length;
    		return lenData;
    	}
    	public byte getStat(){
    		return statField;
    	}
    }

}
