import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class Desert implements Serializable{

	private static final long serialVersionUID = 1L;
	public String name;
	public int width;
	public int height;

	public Desert(String name, int i, int j) {
		// Constructor
		this.name = name;
		this.width = i;
		this.height = j;
	}

	public static void Deserialize() {
		try{
			//Creating an input stream to reconstruct the object from serialised data
			ObjectInputStream in=new ObjectInputStream(new FileInputStream("de.ser"));
			Desert desert=(Desert)in.readObject();
			// Showing the data of the serialised object
			System.out.println("The desert: " + desert.name);
			System.out.println("Has a surface of: " + String.valueOf(desert.width*desert.height) );
			// Closing the stream
			in.close();
			}catch(Exception e){
				System.out.println(e);
				}
			}

	public static void Serialize() {
		try {
			// Creating the object
			Desert desert = new Desert("Mobi", 2000, 1500);
			// Creating output stream and writing the serialised object
			FileOutputStream outfile = new FileOutputStream("de.ser");
			ObjectOutputStream outstream = new ObjectOutputStream(outfile);
			outstream.writeObject(desert);
			outstream.flush();
			// closing the stream
			outstream.close();
			System.out.println("Serialized data saved to de.ser");
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
	public static void main(String args[]) {
		boolean serialize = false;
		
		if (serialize) {
			Desert.Serialize();
		} else {
			Desert.Deserialize();
		}
	}

}
