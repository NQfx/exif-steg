using Steganography.Shared;

namespace Steganography.Core;

public class DataBlock
{
    public int Id { get; set; }
    public bool IsEncrypted { get; set; }
    public byte[]? Data { get; set; }
    public uint OriginalCrc { get; set; }
    public DataBlockType Type { get; set; } 
}

public enum DataBlockType 
{
    UnlinkedData,
    MakerNotes
}
