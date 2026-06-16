using System.ComponentModel.DataAnnotations.Schema;
using System.IO.IsolatedStorage;
using Steganography.Shared;

namespace Steganography.Core;

internal static class ExifScanner
{
    private static int _blocksCount = 0;
    private static int _newId 
    {   get 
        {
            _blocksCount++;
            return _blocksCount;
        }
    }

    public static (List<DataBlock> Blocks,  Dictionary<int, ExifNode> IdTable) GetDataBlocks(ExifGraph graph)
    {
        var blocks = new List<DataBlock>();
        var table = new Dictionary<int, ExifNode>();

        return (blocks, table);
    }

    private static void FindMakerNotesBlocks(ExifGraph graph, List<DataBlock> blocks, Dictionary<int, ExifNode> table)
    {
        var ifds = graph.Nodes.OfType<IfdNode>().ToList();
        foreach (var ifd in ifds)
        {
            foreach (var entry in ifd.Entries)
            {
                if (entry.Tag != 0x927c) continue;
                var data = GetValue(graph, entry);
                
                if (!IsValidData(data)) continue;

                
                
            }
        }
    }

    private static byte[] GetValue(ExifGraph graph, EntryNode entry)
    {
        if (entry.Pointer.Target is null) return entry.InlineData;
        var dataNode = entry.Pointer.Target as DataNode;
        if (dataNode is null) return Array.Empty<byte>();
        return dataNode.Data;
    }

    private static bool IsValidData(byte[] data)
    {
        if (data.Length < 8) return false;
                
        return data[0] == Signatures.Signature 
        && (data[1] == Signatures.EncryptedDataMarker || data[1] == Signatures.UnencryptedDataMarker);
    }
}