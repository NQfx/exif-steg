using System.Buffers.Binary;

namespace Steganography.Shared;

public class FileEditing
{
    public static void WriteJpegAppSegements(List<AppSegment> segments, string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException();

        var originalPos = FileAnalysis.GetAppSegemntsPos(path);
        
    }

    private static byte[] CompileJpegAppSegments(List<AppSegment> segments)
    {
        List<byte> rawData = [];
        foreach (var segment in segments)
        {
            rawData.Add(JpegMarkers.Prefix);
            rawData.Add(segment.Marker);
        }
        return [.. rawData];
    }

    private static void AddUInt32BigEndian(List<byte> list, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        list.AddRange(buffer);
    }
}
