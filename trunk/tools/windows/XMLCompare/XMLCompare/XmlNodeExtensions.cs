using System;
using System.Xml;

namespace Extensions
{
    public static class XmlNodeExtensions
    {
        public static string GetKey(this XmlNode node)
        {
            switch (node.Name)
            {
                case "Process": return "EProcBlockLoc";
                case "Vad":
                case "Module": return "Address";
                case "SDT": return "VirtAddr";
                case "DLL": return "baseAddress";
                case "OpenHandle": return "ID";
                case "RegistryKey": return "Path";
            }

            return string.Empty;
        }

        public static string GetHeading(this XmlNode node)
        {
            switch (node.Name)
            {
                case "Process": return "   Location ADPID       AD Process Name Child    R PID   Rekall Process Name Child\n" +
                                       "   -------- -----  -------------------- -----    -----  -------------------- -----";
                case "Module": return "    Address       AD Module Name      Rekall Module Name\n" +
                                      "-----------  -------------------    --------------------";
                case "Vad": return "    Address AD Start   AD End    Rk Start   Rk End\n" +
                                   "----------- -------- --------    -------- --------";
                case "DLL": return "    Address          AD DLL Name         Rekall DLL Name\n" +
                                   "----------- --------------------   ---------------------";
                case "OpenHandle": return "         ID  Type              AD Path    Type          Rekall Path\n" +
                                          "----------- ----- --------------------   ----- --------------------";
                case "Socket": return "                                   Local Address                                    Remote Address\n" +
                                      "---- ---- ---- ---- ---- ---- ---- ----    -----  ---- ---- ---- ---- ---- ---- ---- ----    -----";
            }

            return string.Empty;
        }

        public static string Format(this XmlNode node)
        {
            if (node == null) return "-----------";

            switch (node.Name)
            {
                case "Process":
                    string pid = node.SelectSingleNode("PID").InnerText;
                    string name = node.SelectSingleNode("Name").InnerText;

                    return string.Format("{0,5}: {1,20} {2,5}", pid, name, node.ChildNodes.Count);

                case "Module":
                    name = node.SelectSingleNode("Name").InnerText;

                    return string.Format("{0,20}", name);

                case "SDT":
                    return string.Format("{0:X} {1}",
                        node.Name, node.ChildNodes.Count);

                case "Vad":
                    string start = node.SelectSingleNode("StartVpn").InnerText;
                    string end = node.SelectSingleNode("EndVpn").InnerText;

                    return string.Format("{0,8} {1,8}", start, end);

                case "DLL":
                    return string.Format("{0,20}", node.SelectSingleNode("Name").InnerText);

                case "OpenHandle":
                    string type = node.SelectSingleNode("Type").InnerText;
                    string path = node.SelectSingleNode("Path").InnerText;

                    return string.Format("{0,5} {1,20}", type, path);

                case "Socket":
                    string local = node.SelectSingleNode("LocalAddress").InnerText;
                    string port = node.SelectSingleNode("Port").InnerText;
                    string remote = node.SelectSingleNode("RemoteAddress").InnerText;
                    string remotePort = node.SelectSingleNode("RemotePort").InnerText;
                    string protocol = node.SelectSingleNode("Proto").InnerText;

                    return string.Format("{0}:{1,5}->{2}:{3,5} {4}", local, port, remote, remotePort, protocol);

            }

            return string.Empty;
        }

        public static string Header(this XmlNode node)
        {
            switch (node.Name)
            {
                case "Process":
                    return string.Format("Process {0:5}: {1,20}",
                        node.SelectSingleNode("PID").InnerText,
                        node.SelectSingleNode("Name").InnerText);

                case "Module":
                    return string.Format("Module {0}", node.SelectSingleNode("Name").InnerText);

                case "Vad":
                    return string.Format("Vad start: {0} end: {1}",
                        node.SelectSingleNode("StartVpn").InnerText,
                        node.SelectSingleNode("EndVpn").InnerText);

                case "DLL":
                    return string.Format("DLL {0}", node.SelectSingleNode("Name").InnerText);

                case "OpenHandle":
                    return string.Format("Open Handle {0}", node.SelectSingleNode("Path").InnerText);


                default:
                    return string.Format("{0}:", node.Name);
            }
        }
    }
}