using Steganography.Shared;

namespace Steganography.Core;

public static class Strategies
{
    public static void AddMakerNotesEntry(ExifGraph graph, byte[] data)
    {
        var header = graph.Nodes.OfType<TiffHeaderNode>().FirstOrDefault();
        var ifd0 = graph.Nodes.OfType<IfdNode>().FirstOrDefault();
        
        if (header is null) throw new Exception("Invalid Exif Struct");
        if (ifd0 is null && header != null) 
        {
            ifd0 = new IfdNode(){Id = 9}; // заменить магическое число на наибольший id + 1
            header.FirstIfd.Target = ifd0;
            graph.AddNode(ifd0);
        }

        var dataNode = new DataNode(){Id = int.MaxValue, Data = data}; // заменить MaxValue на наибольший id + 1

        var entry = ifd0.Entries.Find(e => e.Tag == 0x927c);
        if (entry != null) throw new Exception("This entry already added");
        else entry = new EntryNode(){Tag = 0x927c, Type = 7, Count = (uint)data.Length};
        entry.Pointer.Target = dataNode;

        ifd0.Entries.Add(entry);
        graph.Nodes.Add(dataNode);
    }

}