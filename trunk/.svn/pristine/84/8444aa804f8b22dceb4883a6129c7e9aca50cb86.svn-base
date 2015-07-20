using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using Extensions;
    

namespace XMLCompare
{
    using ComparableNodes = Dictionary<ulong, Tuple<XmlNode, XmlNode>>;
    using PathKeyedNodes = Dictionary<String, Tuple<XmlNode, XmlNode>>;

    class XmlComparer
    {
        private XmlDocument _adDoc = new XmlDocument();
        private XmlDocument _rkDoc = new XmlDocument();

        public bool IsCaseSensitive { get; set; }
        public bool IgnoreGMTOffset { get; set; }

        public XmlComparer(string adFileName, string rkFileName)
        {
            _adDoc.Load(adFileName);
            _rkDoc.Load(rkFileName);
  
            IsCaseSensitive = true;
            IgnoreGMTOffset = true;
        }

        public void Compare()
        {
            XmlNodeList adProcs = _adDoc.DocumentElement.SelectNodes("Process");
            XmlNodeList rkProcs = _rkDoc.DocumentElement.SelectNodes("Process");

            if (adProcs.Count + rkProcs.Count > 0)
            {
                ComparableNodes nodes = compareLists(adProcs, rkProcs, true);
                compareChildren(nodes);
            }

            XmlNodeList adMods = _adDoc.DocumentElement.SelectNodes("Module");
            XmlNodeList rkMods = _rkDoc.DocumentElement.SelectNodes("Module");

            if (adMods.Count + rkMods.Count > 0)
            {
                ComparableNodes nodes = compareLists(adMods, rkMods, true);
                compareChildren(nodes);
            }

            XmlNodeList adSDTs = _adDoc.DocumentElement.SelectNodes("SDTs");
            XmlNodeList rkSDTs = _rkDoc.DocumentElement.SelectNodes("SDTs");

            if (adSDTs.Count + rkSDTs.Count > 0)
                compareSDTs(adSDTs, rkSDTs);

            XmlNodeList adReg = _adDoc.DocumentElement.SelectNodes("RegistryKey");
            XmlNodeList rkReg = _rkDoc.DocumentElement.SelectNodes("RegistryKey");

            if (adReg.Count + rkReg.Count > 0)
                compareLists(adReg, rkReg, true);
        }

        
        protected ComparableNodes evaluateLists(XmlNodeList adNodes, XmlNodeList rkNodes, string xpath)
        {
            ComparableNodes Nodes = new ComparableNodes();

            foreach (XmlNode node in adNodes)
            {
                ulong key;
                if (!ulong.TryParse(node.SelectSingleNode(xpath).InnerText, out key))
                {
                    Console.WriteLine("Unable to convert key value {0} to ulong for node: {1}",
                        node.SelectSingleNode(xpath).InnerText,
                        node.Format());
                    continue;
                }
                if (Nodes.ContainsKey(key))
                {
                    Console.WriteLine("Found duplicate key {0} tagged {1}", key, xpath);
                    continue;
                }
                Nodes.Add(key, new Tuple<XmlNode, XmlNode>(node, null));
            }
            foreach (XmlNode node in rkNodes)
            {
                ulong key;
                if (!ulong.TryParse(node.SelectSingleNode(xpath).InnerText, out key))
                {
                    Console.WriteLine("Unable to convert key value {0} to ulong for node: {1}",
                        node.SelectSingleNode(xpath).InnerText,
                        node.Format());
                    continue;
                }
                if (Nodes.Keys.Contains(key))
                {
                    XmlNode adNode = Nodes[key].Item1;
                    Nodes[key] = new Tuple<XmlNode, XmlNode>(adNode, node);
                }
                else
                {
                    Nodes.Add(key, new Tuple<XmlNode, XmlNode>(null, node));
                }
            }

            return Nodes;
        }

        protected void compareNodes(XmlNode node1, XmlNode node2)
        {
            bool writeMissingHeader = true;
            bool writeHeader = true;
            // children of node1 that are missing from node2
            List<XmlNode> missing1 = new List<XmlNode>();
            // children of node2 that are missing from node1
            List<XmlNode> missing2 = new List<XmlNode>();
            foreach (XmlNode child1 in node1.ChildNodes)
            {
                XmlNode child2 = node2.SelectSingleNode(child1.Name);
                if (child2 == null)
                {
                    missing1.Add(child1);
                }
                else if (child1.Name == "Loaded_DLL_List")
                {
                    XmlNodeList adDLLs = child1.SelectNodes("DLL");
                    XmlNodeList rkDLLs = child2.SelectNodes("DLL");

                    if (adDLLs.Count + rkDLLs.Count > 0)
                    {
                        compareChildren(compareLists(adDLLs, rkDLLs, false));
                    }
                }
                else if (child1.Name == "Open_Sockets_List")
                {
                    XmlNodeList adSockets = child1.SelectNodes("Socket");
                    XmlNodeList rkSockets = child2.SelectNodes("Socket");

                    if (adSockets.Count + rkSockets.Count > 0)
                    {
                        compareSockets(adSockets, rkSockets);
                    }
                }
                else if (child1.Name == "Open_Handles_List")
                {
                    XmlNodeList adHandles = child1.SelectNodes("OpenHandle");
                    XmlNodeList rkHandles = child2.SelectNodes("OpenHandle");

                    if (adHandles.Count + rkHandles.Count > 0)
                    {
                        compareChildren(compareLists(adHandles, rkHandles, false));
                    }
                }
                else if (child1.Name == "Vad_List")
                {
                    XmlNodeList adVads = child1.SelectNodes("Vad");
                    XmlNodeList rkVads = child2.SelectNodes("Vad");
                    
                    if (adVads.Count + rkVads.Count > 0)
                    {
                        compareChildren(compareLists(adVads, rkVads, false));
                    }
                }
                else if (child1.Name == "StartTime" && IgnoreGMTOffset)
                {
                    DateTime adDate, rkDate;
                    if (!DateTime.TryParse(child1.InnerText, out adDate) ||
                        !DateTime.TryParse(child2.InnerText, out rkDate) ||
                        adDate != rkDate)
                    {
                        if (writeHeader)
                        {
                            Console.WriteLine(node1.Header());
                            writeMissingHeader = writeHeader = false;
                        }
                        Console.WriteLine("{0}: {1}   {2}: {3}",
                            child1.Name, child1.InnerText,
                            child2.Name, child2.InnerText);

                    }
                }
                else if ((IsCaseSensitive && (child1.InnerText != child2.InnerText)) ||
                    (child1.InnerText.ToUpper() != child2.InnerText.ToUpper()))
                {
                    if (writeHeader)
                    {
                        Console.WriteLine(node1.Header());
                        writeMissingHeader = writeHeader = false;
                    }
                    Console.WriteLine("{0}: {1}   {2}: {3}",
                        child1.Name, child1.InnerText,
                        child2.Name, child2.InnerText);
                }

            }
            foreach (XmlNode child2 in node2.ChildNodes)
            {
                XmlNode child1 = node1.SelectSingleNode(child2.Name);
                if (child1 == null)
                {
                    missing2.Add(child2);
                }
            }

            if (missing1.Count > 0)
            {
                if (writeMissingHeader)
                {
                    Console.WriteLine(node1.Header());
                    writeMissingHeader = false;
                }

                Console.WriteLine("Missing Rekall Nodes:");
                foreach (XmlNode missing in missing1)
                {
                    Console.WriteLine("{0}: {1}", missing.Name, missing.InnerText);
                }
            }

            if (missing2.Count > 0)
            {
                if (writeMissingHeader)
                {
                    Console.WriteLine(node1.Header());
                    writeMissingHeader = false;
                }
                Console.WriteLine("Missing AD Nodes:");
                foreach (XmlNode missing in missing2)
                {
                    Console.WriteLine("{0}: {1}", missing.Name, missing.InnerText);
                }
            }
        }

        protected ComparableNodes compareLists(XmlNodeList adList, XmlNodeList rkList, bool showCountsWhenIdentical)
        {
            string key = string.Empty;

            if (adList.Count > 0)
            {
                key = adList[0].GetKey();
            }

            if (key == string.Empty)
            {
                Console.WriteLine("Not able to compare these lists.");
                return new ComparableNodes();
            }

            ComparableNodes nodes = evaluateLists(adList, rkList, key);

            if (showCountsWhenIdentical ||
                adList.Count != rkList.Count ||
                adList.Count != nodes.Count)
            {
                Console.WriteLine(adList[0].Name);
                Console.WriteLine("Access Data: {0}", adList.Count);
                Console.WriteLine("Rekall:      {0}", rkList.Count);
                Console.WriteLine("Unique Keys: {0}", nodes.Count);
                Console.WriteLine();

                Console.WriteLine(adList[0].GetHeading());
                foreach (ulong id in nodes.Keys)
                {
                    XmlNode adNode = nodes[id].Item1;
                    XmlNode rkNode = nodes[id].Item2;

                    Console.WriteLine("{0,11} {1}    {2}",
                        id,
                        adNode.Format(),
                        rkNode.Format());
                }
            }

            return nodes;
        }

        protected void compareChildren(ComparableNodes nodes)
        {

            foreach (ulong id in nodes.Keys)
            {
                XmlNode adNode = nodes[id].Item1;
                XmlNode rkNode = nodes[id].Item2;

                if (adNode != null && rkNode != null)
                {
                    compareNodes(adNode, rkNode);
                }
            }
        }

        protected void compareSockets(XmlNodeList adNodes, XmlNodeList rkNodes)
        {
            Dictionary<Tuple<string, int>, Tuple<XmlNode, XmlNode>> sockets =
                new Dictionary<Tuple<string, int>, Tuple<XmlNode, XmlNode>>();

            foreach (XmlNode adNode in adNodes)
            {
                string address = adNode.SelectSingleNode("LocalAddress").InnerText;
                int port = int.Parse(adNode.SelectSingleNode("Port").InnerText);
                Tuple<string, int> key = new Tuple<string, int>(address, port);

                if (sockets.ContainsKey(key))
                {
                    Console.WriteLine("Duplicate socket found: {0}:{1}", key.Item1, key.Item2);
                    continue;
                }

                sockets.Add(key, new Tuple<XmlNode,XmlNode>(adNode, null));
            }
            foreach (XmlNode rkNode in rkNodes)
            {
                string address = rkNode.SelectSingleNode("LocalAddress").InnerText;
                int port = int.Parse(rkNode.SelectSingleNode("Port").InnerText);
                Tuple<string, int> key = new Tuple<string,int>(address, port);

                if (sockets.ContainsKey(key))
                {
                    sockets[key] = new Tuple<XmlNode,XmlNode>(sockets[key].Item1, rkNode);
                }
                else
                {
                    sockets.Add(key, new Tuple<XmlNode,XmlNode>(null, rkNode));
                }
            }

            if (adNodes.Count != rkNodes.Count ||
                adNodes.Count != sockets.Count)
            {
                Console.WriteLine(adNodes[0].Name);
                Console.WriteLine("Access Data: {0}", adNodes.Count);
                Console.WriteLine("Rekall:      {0}", rkNodes.Count);
                Console.WriteLine("Unique Keys: {0}", sockets.Count);
                Console.WriteLine();

                Console.WriteLine(adNodes[0].GetHeading());
                foreach (Tuple<string, int> key in sockets.Keys)
                {
                    XmlNode adNode = sockets[key].Item1;
                    XmlNode rkNode = sockets[key].Item2;

                    Console.WriteLine("{0}   {1}", adNode.Format(), rkNode.Format());
                }

                foreach (Tuple<string, int> key in sockets.Keys)
                {
                    XmlNode adNode = sockets[key].Item1;
                    XmlNode rkNode = sockets[key].Item2;

                    if (adNode != null && rkNode != null)
                    {
                        compareNodes(adNode, rkNode);
                    }
                }
            }
        }

        protected void compareSDTs(XmlNodeList adNodes, XmlNodeList rkNodes)
        {

            ComparableNodes nodes = compareLists(adNodes, rkNodes, true);

            foreach (ulong key in nodes.Keys)
            {
                XmlNode adSDTs = nodes[key].Item1;
                XmlNode rkSDTs = nodes[key].Item2;

                if (adSDTs != null && rkSDTs != null)
                {
                    XmlNodeList adSSDTs = adSDTs.SelectNodes("SSDTs");
                    XmlNodeList rkSSDTs = rkSDTs.SelectNodes("SSDTs");

                    Console.WriteLine("SSDTs: {0} {1}", adSSDTs.Count, rkSSDTs.Count);

                    if (adSSDTs.Count == rkSSDTs.Count)
                    {
                        for (int i = 0; i < adSSDTs.Count; ++i)
                        {
                            Console.WriteLine("Children: {0} {1}", adSSDTs[i].ChildNodes.Count, rkSSDTs[i].ChildNodes.Count);
                            string adVA = adSSDTs[i].SelectSingleNode("VirtAddr").InnerText;
                            string rkVA = rkSSDTs[i].SelectSingleNode("VirtAddr").InnerText;
                            if (adVA != rkVA) Console.WriteLine("Address: {0:X} {1:X}", adVA, rkVA);
                            XmlNodeList adAdds = adSSDTs[i].SelectNodes("SSDTAddr");
                            XmlNodeList rkAdds = rkSSDTs[i].SelectNodes("SSDTAddr");
                            if (adAdds.Count == rkAdds.Count)
                            {
                                for (int addr = 0; addr < adAdds.Count; ++addr)
                                {
                                    if (adAdds[addr].InnerText != rkAdds[addr].InnerText) Console.WriteLine("SSDTAddr: {0:X} {1:X}", adAdds[addr].InnerText, rkAdds[addr].InnerText);
                                }
                            }
                            else Console.WriteLine("SSDTAddrs {0} {1}", adAdds.Count, rkAdds.Count);
                        }
                    }
                }
            }
        }

        protected PathKeyedNodes compareRegistry(XmlNodeList adList, XmlNodeList rkList)
        {
            //string key = string.Empty;

            //if (adList.Count > 0)
            //{
            //    key = adList[0].GetKey();
            //}

            //if (key == string.Empty)
            //{
            //    Console.WriteLine("Not able to compare these lists.");
            //    return new PathKeyedNodes();
            //}

            //ComparableNodes nodes = evaluateLists(adList, rkList, key);

            return new PathKeyedNodes();

        }
    }
}
