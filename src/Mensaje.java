
public class Mensaje {

    /**
     * Representa la cadena contenida en el mensaje
     */
	private Integer cadena;

    /**
     * Método constructor de la clase mensaje
     * @param nCadena Cadena contenida en el mensaje
     */
	public Mensaje(Integer nCadena)
	{
	    cadena = nCadena;
	}

    /**
     * Método necesario para conventir la cadena, de Integer a String
     * @return Cadena en String
     */
    @Override
    public String toString()
    {
	    return Integer.toString(mensaje);
    }

    /**
     * Retorna la cadena contenida en el mensaje
     * @return Cadena contenida en el mensaje
     */
	public int getCadena()
    {
		return cadena;
	}

    /**
     * Actualiza el valor de la Cadena
     * @param nCadenita Nuevo valor de la Cadena
     */
	public void setCadena(Integer nCadenita)
    {
		cadena = nCadenita;
	}
	

}
