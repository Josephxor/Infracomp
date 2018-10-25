package clases;

public class Main
{
	private Cliente cliente;

	public Main()
	{
		cliente= new Cliente();
	}

	public void run()
	{
		try {
			cliente.runCliente();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	public static void main(String[] args)
	{
		Main principal= new Main();
		principal.run();
	}
}
