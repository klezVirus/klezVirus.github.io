import java.nio.file.Files;
import java.nio.file.Paths;
import com.cedarsoftware.util.io.JsonReader;

public class DesertJSON {
     
    public static void main(String[] args) throws Exception {

        // Read JSON as a string
        String json = new String(Files.readAllBytes(Paths.get("desert.json")));
        
        Object desert = JsonReader.jsonToJava(json);
                 
        System.out.println("The desert: " + ((Desert)desert).getName());
		System.out.println("Has a surface of: " + String.valueOf(((Desert)desert).getWidth()*((Desert)desert).getHeight()) );
 
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