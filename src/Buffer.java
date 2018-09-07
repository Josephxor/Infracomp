import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.sql.NClob;
import java.util.ArrayList;
import java.util.Random;

public class Buffer {

    // El número de Servidores
    public Integer nServidores;

    // El número de clientes por atender
	public Integer nClientes;

	// El máximo
    public static Integer maximo = 100;

    // El número de consultas
	public String[] nConsultas;

	// Representa al Buffer
	public static Buffer buff;

	// Lista de Clientes
	public Cliente[] clientes;

	// Lista de Servidores
	public Servidor[] servidores;

    //El array de mensajes, ** COMENZAR IMPLEMENTACIÓN CLASE MENSAJE
	public static ArrayList<Mensaje> msj = new ArrayList<Mensaje>();

    // La uso para saber si un Thread está esperando
    public boolean esperando = false;

    /**
     * Lee, crea y corre las cadenas de clientes, servidores y consultas
     * @param archivo El archivo en el que se especifican los requerimientos de ejecución
     * @throws FileNotFoundException Excepción presentada durante la ejecución de lectura
     * @throws IOException Lanzada en la ejecución del método
     */
	public void Leer(String archivo) throws FileNotFoundException, IOException {

		FileReader f = new FileReader(archivo);
		BufferedReader buffe = new BufferedReader(f);

        String cadena;

		//Saco las cadenas de clientes
		cadena = buffe.readLine();
		nClientes = Integer.parseInt(cadena);
		clientes = new Cliente[nClientes];

		//Saco las cadenas de servidores
		cadenita = buffe.readLine();
		nServidores = Integer.parseInt(cadenita);
		servidores = new Servidor[nServidores];

		//Saco las cadenas de consultas
		cadenota = buffe.readLine();
		nConsults = cadenota.split(",");


		for (Integer i = 0; i < nClientes; i++) {

			Integer[] mensajes = new Integer[Integer.parseInt(nConsultas[i])];

			for (Integer j = 0; j < Integer.parseInt(nConsultas[i]); j++){

			    //mensajes[j] = mirar como generar acá mensajes al azar

			    // ASÍ SERÍA EL CONSTRUCTOR DE CLIENTE, RECIBE UNA LISTA DE INTEGER CON MENSAJES, EL BUFFER Y UN NÚMERO CON LA PETICIÓN **
                clientes[i] = new Cliente(mensajes, buff, Integer.parseInt(nConsultas[i]), );

			}
		}

		//Creo tantos servidores como necesito
		for (Integer i = 0; i < nServidores; i++) {
            servidores[i] = new Servidor(buff);
        }

        //Inicio los servidores creados arriba
		for (Integer i = 0; i < servidores.length; i++){
			servidores[i].start();}

		//Inicio los clientes que cree
		for (int i = 0; i < clientes.length; i++)
			clientes[i].start();

		buffe.close();
	}

	//Aun me faltan métodos

	public static void main(String[] args) throws FileNotFoundException, IOException {
		buff = new Buffer();
		buff.ReadAndRun("./archivo.txt");

		try {
			for (Integer i = 0; i < buff.nClientes; i++)
				buff.clientes[i].join();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		synchronized(buff)
		{
			//Comunicar al servidor que se terminó
			buff.notifyAll();
		}
	}
}
