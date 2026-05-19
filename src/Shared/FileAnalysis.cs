namespace Steganography.Shared;

public static partial class FileAnalysis
{
    public static FileFormat GetFileFormat(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException();
            
        using FileStream stream = File.OpenRead(path);
        if (stream.Length < 8)
            return FileFormat.Unknown;

        byte[] header = new byte[8];
        stream.Read(header, 0, 8);

        if (header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF)
            return FileFormat.Jpeg;

        if (header[0] == 0x89 && header[1] == 0x50 && header[2] == 0x4E &&
            header[3] == 0x47 && header[4] == 0x0D && header[5] == 0x0A &&
            header[6] == 0x1A && header[7] == 0x0A)
            return FileFormat.Png;

        return FileFormat.Unknown;
    }

    public static List<AppSegment> GetJpegAppSegments(string path)
    {
        var segments = new List<AppSegment>();

        if (!File.Exists(path))
            throw new FileNotFoundException();

        using FileStream stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream);

        while (stream.Position < stream.Length)
        {
            byte marker = reader.ReadByte();

            while ((marker == JpegMarkers.Prefix || marker == 0x00) && stream.Position < stream.Length)
            {
                marker = reader.ReadByte();
            }

            if (marker == JpegMarkers.SOI)
                continue;

            if (marker >= JpegMarkers.APP0 && marker <= JpegMarkers.APP0 + 0x0F)
            {
                ushort length = ReadBigEndianUInt16(reader);
                var identifier = ReadNullTerminatedString(reader);

                if (reader.ReadByte() != 0x00)
                    stream.Position -= 1;
                
                int dataLength = length - 2 - identifier.Length;
                byte[]? data = dataLength > 0 ? reader.ReadBytes(dataLength) : null;
                byte[]? tail = GetJpegAppTail(stream, reader);
                
                segments.Add(new AppSegment
                {
                    Marker = marker,
                    Offset = (ulong)stream.Position - length - 2,
                    Length = length,
                    Identifier = identifier,
                    Data = data,
                    Tail = tail
                });
            }
            else break;
        }
        return segments;
    }

    private static byte[] GetJpegAppTail(FileStream stream, BinaryReader reader)
    {
        List<byte>? tail = [];
        while (stream.Position < stream.Length)
        {
            var b = reader.ReadByte();
            if (IsJpegMarker(b))
            {
                stream.Position -= 1;
                break;
            }
            if (b == JpegMarkers.Prefix)
                continue;
            tail.Add(b);
        }
        return [.. tail];
    }

    private static bool IsJpegMarker(byte b) => (b >= 0xC0 && b <= 0xFE) || b == 0xD8 || b == 0xD9;

    private static ushort ReadBigEndianUInt16(BinaryReader reader)
    {
        byte high = reader.ReadByte();
        byte low = reader.ReadByte();
        return (ushort)((high << 8) | low);
    }

    private static byte[] ReadNullTerminatedString(BinaryReader reader)
    {
        var bytes = new List<byte>();
        byte b;
        
        while ((b = reader.ReadByte()) != 0)
            bytes.Add(b);
        
        bytes.Add(0);
        return [.. bytes];
    }
}

public class AppSegment
{
    public byte Marker { get; set; }
    public int AppNumber => Marker - 0xE0;
    public ulong Offset { get; set; }
    public ushort Length { get; set; }
    public byte[]? Identifier { get; set; }
    public byte[]? Data { get; set; }
    public byte[]? Tail { get; set; }
}

public enum FileFormat
{
    Jpeg,
    Png,
    Unknown
}

internal static class JpegMarkers
{
    public const byte Prefix = 0xFF;
    public const byte SOI  = 0xD8;
    public const byte EOI  = 0xD9;
    public const byte APP0 = 0xE0;
}
