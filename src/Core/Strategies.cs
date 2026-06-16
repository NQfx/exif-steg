using System.Buffers.Binary;
using Steganography.Shared;
using Steganography.Shared.Utils;

namespace Steganography.Core;

public static class Strategies
{
    public static void AddMakerNotesEntry(ExifGraph graph, byte[] data, bool isEncrypted = false)
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

        var dataHeader = GetDataHeader(data, isEncrypted);
        var dataNode = new DataNode(){Id = int.MaxValue, Data = [.. dataHeader, .. data]}; // заменить MaxValue на наибольший id + 1

        var entry = ifd0.Entries.Find(e => e.Tag == 0x927c);
        if (entry != null) throw new Exception("This entry already added");
        else entry = new EntryNode(){Tag = 0x927c, Type = 7, Count = (uint)data.Length};
        entry.Pointer.Target = dataNode;

        ifd0.Entries.Add(entry);
        graph.Nodes.Add(dataNode);
    }

    private static byte[] GetDataHeader(byte[] data, bool isEncrypted)
    {
        var header = new List<byte>(){Signatures.Signature};
        var dataMarker = isEncrypted ? Signatures.EncryptedDataMarker : Signatures.UnencryptedDataMarker;
        header.Add(dataMarker);

        var crc = ConvertUint32ToBigEndianBytes(Crc32.ComputeCrc32(data)); // Crc32 хэш-сумма только самого блока данных 
        header.AddRange(crc);
        
        var length = ConvertUint32ToBigEndianBytes((uint)data.Length); // Длина только самого блока данных
        header.AddRange(length);
        
        return [.. header];
    }

    private static byte[] ConvertUint32ToBigEndianBytes(uint value)
    {
        byte[] buffer = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        return buffer;
    }


}