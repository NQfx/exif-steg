using System.Text;

namespace Steganography.Shared;

public abstract class ExifNode
{
    public long Id { get; set; }
    public uint FinalOffset { get; internal set; }
    public abstract int Size { get; }
    public abstract void Write(byte[] buffer, Dictionary<long, uint> map, bool isLittleEndian);
}

public class ExifPointer
{
    public ExifNode Target { get; set; }
    public uint GetAddress(Dictionary<long, uint> map) =>
        (Target != null && map.TryGetValue(Target.Id, out var addr)) ? addr : 0;
}

public class TiffHeaderNode : ExifNode
{
    public override int Size => 8; 
    public ExifPointer FirstIfd { get; set; } = new ExifPointer();

    public override void Write(byte[] buffer, Dictionary<long, uint> map, bool isLittleEndian)
    {
        var signature = isLittleEndian ? "II" : "MM";
        Encoding.ASCII.GetBytes(signature).CopyTo(buffer, FinalOffset);
        WriteUInt16(buffer, FinalOffset + 2, 42, isLittleEndian);
        WriteUInt32(buffer, FinalOffset + 4, FirstIfd.GetAddress(map), isLittleEndian);
    }

    private void WriteUInt16(byte[] buffer, uint offset, ushort d, bool endian) {
        var data = BitConverter.GetBytes(d); 
        if (endian != BitConverter.IsLittleEndian) 
            Array.Reverse(data);
        data.CopyTo(buffer, offset);
    }
    private void WriteUInt32(byte[] buffer, uint offset, uint d, bool endian) {
        var data = BitConverter.GetBytes(d); 
        if (endian != BitConverter.IsLittleEndian) 
            Array.Reverse(data);
        data.CopyTo(buffer, offset);
    }
}

public class EntryNode
{
    public ushort Tag { get; set; }
    public ushort Type { get; set; }
    public uint Count { get; set; } 
    public ExifPointer Pointer { get; set; } = new ExifPointer();
    public byte[] InlineData { get; set; } = new byte[4];

    public void Write(byte[] buffer, uint offset, Dictionary<long, uint> map, bool isLittleEndian)
    {
        Write(buffer, offset, Tag, isLittleEndian);
        Write(buffer, offset + 2, Type, isLittleEndian);
        Write(buffer, offset + 4, Count, isLittleEndian);

        if (Pointer.Target != null)
            Write(buffer, offset + 8, Pointer.GetAddress(map), isLittleEndian);
        else
            Array.Copy(InlineData, 0, buffer, offset + 8, 4);
    }

    private void Write<T>(byte[] b, uint off, T v, bool le) where T : struct {
        dynamic val = v; 
        byte[] data = BitConverter.GetBytes(val);
        if (le != BitConverter.IsLittleEndian) 
            Array.Reverse(data);
        data.CopyTo(b, off);
    }
}

public class IfdNode : ExifNode
{
    public List<EntryNode> Entries { get; } = new List<EntryNode>();
    public ExifPointer NextIfd { get; set; } = new ExifPointer();

    public override int Size => 2 + (Entries.Count * 12) + 4;

    public override void Write(byte[] buffer, Dictionary<long, uint> map, bool isLittleEndian)
    {
        var countBytes = BitConverter.GetBytes((ushort)Entries.Count);
        if (isLittleEndian != BitConverter.IsLittleEndian) Array.Reverse(countBytes);
        countBytes.CopyTo(buffer, FinalOffset);

        for (int i = 0; i < Entries.Count; i++)
            Entries[i].Write(buffer, FinalOffset + 2 + (uint)(i * 12), map, isLittleEndian);

        var nextAddr = BitConverter.GetBytes(NextIfd.GetAddress(map));
        if (isLittleEndian != BitConverter.IsLittleEndian) 
            Array.Reverse(nextAddr);
        nextAddr.CopyTo(buffer, FinalOffset + (uint)Size - 4);
    }
}

public class DataNode : ExifNode
{
    public ExifDataType Type;
    public byte[] Data { get; set; } = Array.Empty<byte>();
    public override int Size => Data.Length;
    public override void Write(byte[] buffer, Dictionary<long, uint> map, bool isLittleEndian)
    {
        if (Size > 0) Array.Copy(Data, 0, buffer, FinalOffset, Size);
    }
}

public class ExifGraph
{
    private readonly List<ExifNode> _nodes = [];
    public bool IsLittleEndian { get; set; } = true;

    public List<ExifNode> Nodes => _nodes;

    public void AddNode(ExifNode node) => _nodes.Add(node);

    public void InsertAfter(ExifNode anchor, ExifNode newNode)
    {
        int idx = _nodes.IndexOf(anchor);
        _nodes.Insert(idx + 1, newNode);
    }

    public void RemoveNode(ExifNode node)
    {
        _nodes.Remove(node);
        foreach (var ifd in _nodes.OfType<IfdNode>())
        {
            if (ifd.NextIfd.Target == node) 
                ifd.NextIfd.Target = null;
                
            foreach (var e in ifd.Entries.Where(e => e.Pointer.Target == node)) 
                e.Pointer.Target = null;
        }
    }

    public byte[] Compile()
    {
        uint currentPtr = 0;
        var offsetMap = new Dictionary<long, uint>();

        foreach (var node in _nodes)
        {
            node.FinalOffset = currentPtr;
            offsetMap[node.Id] = currentPtr;
            currentPtr += (uint)node.Size;
        }

        byte[] buffer = new byte[currentPtr];
        foreach (var node in _nodes)
        {
            node.Write(buffer, offsetMap, IsLittleEndian);
        }
        return buffer;
    }
}

public enum ExifDataType
{
    Unlinked,
    Linked
}

internal class ExifBlock 
{
    public ExifBlockType Type { get; set; }
    public int Offset { get; set; }
    public int Length { get; set; }
}

public enum ExifBlockType
{
    Unknown,
    TiffHeader,
    Ifd,
    Data
}
