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
    public ExifNode? Target { get; set; }
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
        Encoding.ASCII.GetBytes(signature).CopyTo(buffer, (int)FinalOffset);
        WriteUInt16(buffer, FinalOffset + 2, 42, isLittleEndian); 
        WriteUInt32(buffer, FinalOffset + 4, FirstIfd.GetAddress(map), isLittleEndian);
    }

    private void WriteUInt16(byte[] buffer, uint offset, ushort d, bool endian)
    {
        var data = BitConverter.GetBytes(d);
        if (endian != BitConverter.IsLittleEndian)
            Array.Reverse(data);
        data.CopyTo(buffer, (int)offset);
    }

    private void WriteUInt32(byte[] buffer, uint offset, uint d, bool endian)
    {
        var data = BitConverter.GetBytes(d);
        if (endian != BitConverter.IsLittleEndian)
            Array.Reverse(data);
        data.CopyTo(buffer, (int)offset);
    }
}


public class EntryNode : ExifNode
{
    public ushort Tag { get; set; }
    public ushort Type { get; set; }
    public uint Count { get; set; } 
    public uint? ValueOffset { get; set; }
    public ExifPointer Pointer { get; set; } = new ExifPointer();
    public byte[] InlineData { get; set; } = new byte[4];

    public override int Size => 12;

    public override void Write(byte[] buffer, Dictionary<long, uint> map, bool isLittleEndian)
    {
        WriteUInt16(buffer, FinalOffset, Tag, isLittleEndian);
        WriteUInt16(buffer, FinalOffset + 2, Type, isLittleEndian);
        WriteUInt32(buffer, FinalOffset + 4, Count, isLittleEndian);

        if (Pointer.Target != null)
        {
            WriteUInt32(buffer, FinalOffset + 8, Pointer.GetAddress(map), isLittleEndian);
        }
        else if (ValueOffset.HasValue)
        {
            WriteUInt32(buffer, FinalOffset +8, ValueOffset.Value, isLittleEndian);
        }
        else if (InlineData != null && InlineData.Length == 4)
        {
            Array.Copy(InlineData, 0, buffer, FinalOffset + 8, 4);
        }
        else
        {
            for (int i = 0; i < 4; i++)
                buffer[FinalOffset + 8 + i] = 0;
        }
    }

    private void WriteUInt16(byte[] buffer, uint offset, ushort value, bool isLittleEndian)
    {
        var data = BitConverter.GetBytes(value);
        if (isLittleEndian != BitConverter.IsLittleEndian)
            Array.Reverse(data);
        Array.Copy(data, 0, buffer, offset, 2);
    }

    private void WriteUInt32(byte[] buffer, uint offset, uint value, bool isLittleEndian)
    {
        var data = BitConverter.GetBytes(value);
        if (isLittleEndian != BitConverter.IsLittleEndian)
            Array.Reverse(data);
        Array.Copy(data, 0, buffer, offset, 4);
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
        if (isLittleEndian != BitConverter.IsLittleEndian) 
            Array.Reverse(countBytes);
        Array.Copy(countBytes, 0, buffer, FinalOffset, 2);

        uint entryOffset = FinalOffset + 2;
        foreach (var entry in Entries)
        {
            entry.FinalOffset = entryOffset; 
            entry.Write(buffer, map, isLittleEndian);
            entryOffset += 12;
        }

        var nextAddr = BitConverter.GetBytes(NextIfd.GetAddress(map));
        if (isLittleEndian != BitConverter.IsLittleEndian) 
            Array.Reverse(nextAddr);
        Array.Copy(nextAddr, 0, buffer, FinalOffset + (uint)Size - 4, 4);
    }
}

public class DataNode : ExifNode
{
    public ExifDataType Type;
    public byte[] Data { get; set; } = Array.Empty<byte>();
    
    public override int Size 
    {
        get 
        {
            int size = Data.Length;
            return (size % 2 == 0) ? size : size + 1;
        }
    }
    
    public override void Write(byte[] buffer, Dictionary<long, uint> map, bool isLittleEndian)
    {
        if (Data.Length > 0)
        {
            Array.Copy(Data, 0, buffer, FinalOffset, Data.Length);
            
            if (Data.Length % 2 != 0)
                buffer[FinalOffset + Data.Length] = 0;
        }
    }
}

public class ExifGraph
{
    private List<ExifNode> _nodes = [];
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
        SortNodes();
        uint currentPtr = 0;
        var offsetMap = new Dictionary<long, uint>();

        foreach (var node in _nodes)
        {
            if (node is DataNode && currentPtr % 2 != 0)
                currentPtr += 1;
                
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

    public void SortNodes()
    {
        _nodes = [.. _nodes.OrderBy(n => n.Id)];
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
    public long Offset { get; set; }
    public long Length { get; set; }
}

public enum ExifBlockType
{
    TiffHeader,
    Ifd,
    Data,
    UnlinkedData
}
