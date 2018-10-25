package clases;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.DecimalFormat;
import java.util.Random;

import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Protocolo
{

	//--------------------------------------------------------------------
	//CONSTANTES
	//--------------------------------------------------------------------

	public static final String ACTUALIZACION="ACT";
	public static final String ALGORITMOS="ALGORITMOS";
	public static final String ALG_AES="AES";
	public static final String ALG_BLOWFISH="BLOWFISH";
	public static final String ALG_RSA="RSA";
	public static final String ALG_HMACMD5="HMACMD5";
	public static final String ALG_HMACSHA1="HMACSHA1";
	public static final String ALG_HMACSHA256="HMACSHA256";
	public static final String BOUNCY_CASTLE="BC";
	public static final String CERTIFICADO_CLIENTE="CERTCLNT";
	public static final String CERTIFICADO_SERVIDOR="CERTSRV";
	public static final String ESTADO="ESTADO";
	public static final String ESTADO_OK="OK";
	public static final String ESTADO_ERROR="ERROR";
	public static final String HOLA= "HOLA";
	public static final String HOST="localhost";
	public static final String INICIO="INICIO";
	public static final Integer PUERTO=8080;
	public static final String SEPARADOR=":";


	//--------------------------------------------------------------------
	//ATRIBUTOS
	//--------------------------------------------------------------------
	private Integer numeroActualizacion;
	private KeyPairGenerator generadorLlaves;

	/**
	*Metodo constuctos de la clase protocolo
	*/
	public Protocolo() throws CertificateException
	{
		try {
			generadorLlaves= KeyPairGenerator.getInstance(ALG_RSA, BOUNCY_CASTLE);
			generadorLlaves.initialize(1024, new SecureRandom());
		}
		catch (NoSuchAlgorithmException e) {
			e.printegerStackTrace();
		}
		catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
		numeroActualizacion = 1;
	}

	public Integer darNumeroActualizacion()
	{
		return numeroActualizacion;
	}

	public void aumentarNumeroActualizacion()
	{
		numeroActualizacion++;
	}

	public KeyPair generarLlaves()
	{
		return generadorLlaves.generateKeyPair();
	}

	public String generarCoordenadas()
	{
		Random random= new Random();
		double num1=1000*random.nextDouble();
		double num2=2000*random.nextDouble();

		return num1+","+num2;
	}

	public KeyPairGenerator darGenerador()
	{
		return generadorLlaves;
	}

}
