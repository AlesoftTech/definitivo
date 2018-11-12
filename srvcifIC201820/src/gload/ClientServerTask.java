package gload;

import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.Client;

public class ClientServerTask extends Task{
	

	@Override
	public void fail() {
		// TODO Auto-generated method stub
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		// TODO Auto-generated method stub
		System.out.println(Task.OK_MESSAGE);
		
	}

	@Override
	public void execute() {
		// TODO Auto-generated method stub
		Client client = new Client(); 
		client.sendMessageToServer("Hola Amigos! soy un cliente");
		client.waitForMessageFromServer();
	}
	
	

}
