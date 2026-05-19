namespace Steganography.Shared;
public class BytesReader
{
    private readonly byte[] _data;
    private int _position;
    
    public bool IsLittleEndian { get; set; }
    public int Position => _position;
    public int Length => _data.Length;
    
    public BytesReader(byte[] data)
    {
        _data = data;
        _position = 0;
        IsLittleEndian = true;
    }
    
    public void Seek(int position)
    {
        if (position < 0 || position >= _data.Length)
            throw new ArgumentOutOfRangeException();
        _position = position;
    }
    
    public byte ReadByte() => _position < _data.Length ? _data[_position++] : (byte)0;
    
    public ushort ReadUInt16()
    {
        if (_position + 2 > _data.Length)
            throw new InvalidOperationException();
        
        if (IsLittleEndian)
            return (ushort)(_data[_position++] | (_data[_position++] << 8));
        else
            return (ushort)((_data[_position++] << 8) | _data[_position++]);
    }
    
    public uint ReadUInt32()
    {
        if (_position + 4 > _data.Length)
            throw new InvalidOperationException();
        
        if (IsLittleEndian)
        {
            return (uint)(_data[_position++] | (_data[_position++] << 8) | (_data[_position++] << 16) | (_data[_position++] << 24));
        }
        else
        {
            return (uint)((_data[_position++] << 24) | (_data[_position++] << 16) | (_data[_position++] << 8) | _data[_position++]);
        }
    }
    
    public byte[] ReadBytes(int count)
    {
        if (_position + count > _data.Length)
            throw new InvalidOperationException();
        
        var result = new byte[count];
        Array.Copy(_data, _position, result, 0, count);
        _position += count;
        return result;
    }
    
    public byte[] ReadBytes(uint count) => ReadBytes((int)count);
}