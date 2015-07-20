using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;


namespace XMLCompare
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("XmlComparcome [ad xml file] [rekall xml file]");
                return;
            }

            XmlComparer comparer = new XmlComparer(args[0], args[1]);
            comparer.IsCaseSensitive = false;

            comparer.Compare();
        }
    }
}
