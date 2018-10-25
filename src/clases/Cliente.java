package clases;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Set;

import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi;
import org.bouncycastle.jcajce.provider.digest.SHA256.HashMac;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;




public class Cliente
{
	private Protocolo protocolo;
	private Socket so;
	private PrintWriter escritor;
	private BufferedReader lector;
	private X509Certificate certificado;
	private X509Certificate certificadoServidor;
	private KeyPair llaves;

	public Cliente()
	{
		Security.addProvider(new BouncyCastleProvider());

	}
	public synchronized void runCliente() throws Exception
	{
		protocolo = new Protocolo();
		try
		{
			so= new Socket(protocolo.HOST,protocolo.PUERTO);
			escritor= new PrintWriter(so.getOutputStream(),true);
			saludar();
			if(Verificar(recibir(), protocolo.INICIO))
			{
				enviarAlgoritmos();

				if(Verificar(recibir(),protocolo.ESTADO+protocolo.SEPARADOR+protocolo.ESTADO_OK))
				{
					crearLlaves();
					generarCertificado();
					autenticar();
					enviarCertificado();
					if(Verificar(recibir(), protocolo.ESTADO+protocolo.SEPARADOR+protocolo.ESTADO_OK))
					{
						if(Verificar(recibir(), protocolo.CERTIFICADO_SERVIDOR))
						{

							VerificarCertificado();
							escribir(protocolo.ESTADO+protocolo.SEPARADOR+protocolo.ESTADO_OK);
							String llave=recibir();
							if(Verificar(llave.split(":")[0], protocolo.INICIO))
							{
								String coordenadas= protocolo.generarCoordenadas();

								String llave16= llave.split(":")[1];
								byte[] arr= DatatypeConverter.parseHexBinary(llave10);
								byte[] llavebytes=desencriptar(protocolo.ALG_RSA, arr);

								byte[] mensaje=encriptar(protocolo.ALG_AES,llavebytes,coordenadas);
								String mensajito=DatatypeConverter.printHexBinary(mensaje);

								String mensajeListo= protocolo.ACTUALIZACION+
								protocolo.darNumeroActualizacion()+
								protocolo.SEPARADOR+mensajito;

								protocolo.aumentarNumeroActualizacion();
								escribir(mensajeListo);

								byte[] mensaje2=encriptar2(protocolo.ALG_HMACSHA256, llavebytes,coordenadas);
								String mensajito2=DatatypeConverter.printHexBinary(mensaje2);

								String mensajeListo2= protocolo.ACTUALIZACION+
								protocolo.darNumeroActualizacion()+
								protocolo.SEPARADOR+mensajito2;

								escribir(mensajeListo2);
							}
						}
					}
				}
			}
			else
			{
				throw new Exception("Error en la comunicacion con el servidor");
			}
			escritor.close();
			lector.close();
			so.close();
		}
		catch (UnknownHostException e)
		{
			e.printStackTrace();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}

	private void saludar() throws UnknownHostException,IOException
	{

		escribir(protocolo.HOLA);

	}

	private  void enviarAlgoritmos() throws UnknownHostException,IOException
	{
		String cadena=
		protocolo.ALGORITMOS+
		protocolo.SEPARADOR+
		protocolo.ALG_AES+
		protocolo.SEPARADOR+
		protocolo.ALG_RSA+
		protocolo.SEPARADOR+
		protocolo.ALG_HMACSHA256;
		escribir(cadena);
	}

	private void autenticar() throws UnknownHostException, IOException
	{
		escribir(protocolo.CERTIFICADO_CLIENTE);
	}

	private void escribir(String cadena) throws UnknownHostException,IOException
	{
		escritor.println(cadena);
	}

	private  String recibir() throws IOException
	{
		String entrada="";
		try{
			lee= new BufferedReader(new InputStreamReader(so.getInputStream()));
			entra=lee.readLine();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return entra;
	}

	private boolean Verificar(String primero, String segundo)
	{
		Boolean rta = false;
		if(primero!=null)
		{
			if(primero.equals(segundo))
			{
				rta = true;
			}
		}
		return rta;
	}

	private void generarCertificado() throws Exception
	{
		X509V3CertificateGenerator certifGen= new X509V3CertificateGenerator();
		X500Principal nombre= new X500Principal("cn=Jose");
		certifGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certifGen.setSubjectDN(new X509Name("dc=Jose"));
		certifGen.setIssuerDN(nombre);
		/**
		Revisa acá
		*/
		certifGen.setNotBefore(new Date());
		Date nueva = new Date();
		nueva.setYear(2019);
		certifGen.setNotAfter(nueva);
		certifGen.setPublicKey(llaves.getPublic());
		certifGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		certifGen.addExtension(X509Extensions.ExtendedKeyUsage,
		true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));

		try
		{
			certificado=certifGen.generate(llaves.getPrivate(),protocolo.BOUNCY_CASTLE);
		}
		catch (CertificateEncodingException e)
		{
			throw new Exception("1. No se pudo generar el certificado");
		}
		catch (InvalidKeyException e)
		{
			throw new Exception("2. No se pudo generar el certificado");
		}
		catch (IllegalStateException e)
		{
			e.printStackTrace();
			throw new Exception("3. No se pudo generar el certificado");
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new Exception("4. No se pudo generar el certificado");
		}
		catch (SignatureException e)
		{
			throw new Exception("5. No se pudo generar el certificado");
		}

	}
//ACÁ QUEDÉ
	private void enviarCertificado() throws CertificateEncodingException, IOException
	{
		so.getOutputStream().write(certificado.getEncoded());
		so.getOutputStream().flush();
	}
	private void crearLlaves()
	{
		llaves= protocolo.generarLlaves();
	}
	private void VerificarCertificado() throws UnknownHostException, IOException
	{
		try
		{
			byte bytesCertificado[] = new byte[5000];
			so.getInputStream().read(bytesCertificado);
			InputStream llegada = new ByteArrayInputStream(bytesCertificado);
			CertificateFactory fabrica = CertificateFactory.getInstance("X.509");
			X509Certificate servidor=(X509Certificate)fabrica.generateCertificate(llegada);
			certificadoServidor=servidor;
		}
		catch (Exception e)
		{
			escribir(protocolo.ESTADO+protocolo.SEPARADOR+protocolo.ESTADO_ERROR);
		}
	}
	private byte[] desencriptar(String algoritmo,byte[] datos) throws Exception
	{
		try
		{
			Cipher desencriptador= Cipher.getInstance(algoritmo);
			desencriptador.init(Cipher.DECRYPT_MODE, llaves.getPrivate());
			return desencriptador.doFinal(datos);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			throw new Exception("Error al decifrar");
		}

	}
	private byte[] encriptar(String algoritmo,byte[] llaveBytes,String encriptable) throws Exception
	{
		try
		{

			SecretKey secreta = new SecretKeySpec(llaveBytes,0,16,algoritmo);
			Cipher encriptador= Cipher.getInstance(algoritmo);
			encriptador.init(Cipher.ENCRYPT_MODE, secreta);
			return encriptador.doFinal(encriptable.getBytes());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			throw new Exception("Error al cifrar");
		}

	}
	private byte[] encriptar2(String algoritmo,byte[] llaveBytes,String encriptable) throws Exception
	{
		try
		{
			SecretKey secreta = new SecretKeySpec(llaveBytes,0,16,"RSA");
			Mac mac=Mac.getInstance("HMACSHA256");
			mac.init(secreta);
			byte[] hasheado= mac.doFinal(encriptable.getBytes());
			Cipher encriptador= Cipher.getInstance("RSA");
			encriptador.init(Cipher.ENCRYPT_MODE, certificadoServidor.getPublicKey());
			return encriptador.doFinal(hasheado);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			throw new Exception("Error al cifrar");
		}

	}

}
