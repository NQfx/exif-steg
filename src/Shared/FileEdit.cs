using System.Buffers.Binary;

namespace Steganography.Shared;

public class FileEdit
{
    public static void OverwriteJpegAppSegements(List<AppSegment> segments, string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException();

        var (Start, End) = FileAnalysis.GetAppSegemntsPos(path);
        if (Start == -1)
        {
            Start = 2;
            End = 2;
        }
        var newData = CompileJpegAppSegments(segments);
        OverwriteBlock(path, newData, Start, End);
    }

    public static void OverwritePngChunks(List<PngChunk> chunks, string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException();
        
        var (Start, End) = (8, GetFileLength(path));

        var newData = CompilePngChunks(chunks);
        OverwriteBlock(path, newData, Start, End);
    }

    private static void OverwriteBlock(string filePath, byte[] newData, long startIndex, long endIndex)
    {
        using var stream = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite);
        long oldLength = endIndex - startIndex;
        long diff = newData.Length - oldLength;

        if (diff != 0)
        {
            stream.Position = endIndex;
            byte[] tail = new byte[stream.Length - endIndex];
            stream.Read(tail, 0, tail.Length);

            stream.SetLength(stream.Length + diff);
            stream.Position = startIndex + newData.Length;
            stream.Write(tail, 0, tail.Length);
        }

        stream.Position = startIndex;
        stream.Write(newData, 0, newData.Length);
    }

    private static byte[] CompilePngChunks(List<PngChunk> chunks)
    {
        List<byte> rawData = [];
        foreach (var chunk in chunks)
        {

            uint chunkLength = chunk.Data != null ? (uint)chunk.Data.Length : 0;
            AddUInt32BigEndian(rawData, chunkLength);

            if (chunk.Type != null) rawData.AddRange(chunk.Type);
            if (chunk.Data != null) rawData.AddRange(chunk.Data);

            byte[] forCrcData = [];

            if (chunk.Type != null)
                forCrcData = chunk.Type;

            if (chunk.Data != null)
                forCrcData = [.. forCrcData, .. chunk.Data];

            uint chunkCrc = ComputeCrc32(forCrcData);
            AddUInt32BigEndian(rawData, chunkCrc);
            
        }
        return [.. rawData];
    }

    private static byte[] CompileJpegAppSegments(List<AppSegment> segments)
    {
        List<byte> rawData = [];
        foreach (var segment in segments)
        {
            rawData.Add(JpegMarkers.Prefix);
            rawData.Add(segment.Marker);

            ushort segmentLength = 2;
            if (segment.Identifier != null) segmentLength += (ushort)segment.Identifier.Length;
            else throw new Exception("Identifier is null");
            if (segment.Data != null) segmentLength += (ushort)segment.Data.Length;
            if (segment.Tail != null) segmentLength += (ushort)segment.Tail.Length;

            AddUInt16BigEndian(rawData, segmentLength);

            if (segment.Identifier != null) rawData.AddRange(segment.Identifier);
            if (segment.Data != null) rawData.AddRange(segment.Data);
            if (segment.Tail != null) rawData.AddRange(segment.Tail);
        }
        return [.. rawData];
    }

    private static uint ComputeCrc32(byte[] data)
    {
        const uint polynomial = 0xEDB88320;
        uint crc = 0xFFFFFFFF;

        foreach (byte b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ polynomial : crc >> 1;
        }

        return ~crc;
    }

    private static long GetFileLength(string path)
    {
        long fileLength;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read);
        fileLength = stream.Length;
        return fileLength;
    }

    private static void AddUInt32BigEndian(List<byte> list, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        list.AddRange(buffer);
    }

    private static void AddUInt16BigEndian(List<byte> list, ushort value)
    {
        Span<byte> buffer = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(buffer, value);
        list.AddRange(buffer);
    }
}
