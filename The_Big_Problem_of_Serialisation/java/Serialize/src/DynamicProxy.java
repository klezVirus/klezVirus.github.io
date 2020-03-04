import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;

public class DynamicProxy implements InvocationHandler {
		  
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) 
      throws Throwable {
        System.out.println("Invoked method: " + method.getName());
 
        return method.getName();
    }

	public static void test(String args[]) {
		Map proxyInstance = (Map) Proxy.newProxyInstance(
		DynamicProxy.class.getClassLoader(), 
		new Class[] { Map.class }, 
		new DynamicProxy());
		
		System.out.println(proxyInstance.toString());
	}
	
}
