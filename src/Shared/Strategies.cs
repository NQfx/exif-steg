using System.Text;

namespace Steganography.Shared;
public static class Strategies {

    public static void AddMakerNotesEntry(ExifGraph graph, byte[] data)
    {
        var header = graph.Nodes.OfType<TiffHeaderNode>().FirstOrDefault();
        var ifd0 = graph.Nodes.OfType<IfdNode>().FirstOrDefault();
        
        if (header is null) throw new Exception("Invalid Exif Struct");
        if (ifd0 is null && header != null) 
        {
            ifd0 = new IfdNode(){Id = 9};
            header.FirstIfd.Target = ifd0;
            graph.AddNode(ifd0);
        }

        var dataNode = new DataNode(){Id = int.MaxValue, Data = data};

        var entry = ifd0.Entries.Find(e => e.Tag == 0x927c);
        if (entry != null) throw new Exception("This entry already added");
        else entry = new EntryNode(){Tag = 0x927c, Type = 7, Count = (uint)data.Length};
        entry.Pointer.Target = dataNode;

        ifd0.Entries.Add(entry);
        graph.Nodes.Add(dataNode);
    }


    public static void WriteStrategieLegacy(byte[] data, string path,bool isDeleteData = false, string? outputPath = null) {
        if (!File.Exists(path)) throw new FileNotFoundException(path);
        if (FileAnalysis.GetFileFormat(path) != FileFormat.Jpeg) throw new InvalidOperationException("File is not JPEG");
        outputPath ??= path;
        byte[] jpeg = File.ReadAllBytes(path);
        // Íîâûé EXIF payload
        // APP1 = "Exif\0\0" + TIFF DATA
        byte[] exifHeader = Encoding.ASCII.GetBytes("Exif\0\0");

        byte[] exifPayload = new byte[exifHeader.Length + data.Length];

        Buffer.BlockCopy(exifHeader, 0, exifPayload, 0, exifHeader.Length);
        Buffer.BlockCopy(data, 0, exifPayload, exifHeader.Length, data.Length);
        if (isDeleteData) { exifPayload = []; }
        // APP1 length:
        // âêëþ÷àåò ñâîè 2 áàéòà äëèíû
        ushort app1Length = (ushort)(exifPayload.Length + 2);
        using MemoryStream input = new MemoryStream(jpeg);
        using BinaryReader reader = new BinaryReader(input);
        using MemoryStream output = new MemoryStream();
        using BinaryWriter writer = new BinaryWriter(output);
        
        ushort soi = ReadBigEndianUInt16(reader);

        if (soi != 0xFFD8)
            throw new InvalidOperationException("Invalid JPEG");

        WriteBigEndianUInt16(writer, soi);
        bool exifWritten = false;
        while (input.Position < input.Length) {
            byte prefix = reader.ReadByte();
            if (prefix != 0xFF)
                throw new InvalidOperationException("Invalid JPEG marker");
            byte marker = reader.ReadByte();
            // äàëüøå èä¸ò image stream
            if (marker == 0xDA) {
                // Åñëè EXIF åù¸ íå âñòàâëåí — âñòàâëÿåì ïåðåä 0xDA
                if (!exifWritten) {
                    WriteApp1(writer, app1Length, exifPayload);
                    exifWritten = true;
                }
                writer.Write((byte)0xFF);
                writer.Write(marker);

                ushort sosLength = ReadBigEndianUInt16(reader);

                WriteBigEndianUInt16(writer, sosLength);

                byte[] sosData = reader.ReadBytes(sosLength - 2);
                writer.Write(sosData);

                byte[] imageData = reader.ReadBytes((int)(input.Length - input.Position));
                writer.Write(imageData);
                break;
            }

            // standalone markers
            if (marker == 0xD8 || marker == 0xD9) {
                writer.Write((byte)0xFF);
                writer.Write(marker);
                continue;
            }
            ushort length = ReadBigEndianUInt16(reader);
            byte[] segmentData = reader.ReadBytes(length - 2);
            bool isExif =
                marker == 0xE1 &&
                segmentData.Length >= 6 &&
                segmentData[0] == 0x45 &&
                segmentData[1] == 0x78 &&
                segmentData[2] == 0x69 &&
                segmentData[3] == 0x66 &&
                segmentData[4] == 0x00 &&
                segmentData[5] == 0x00;

            
            if (isExif) {
                // Âñòàâëÿåì íîâûé òîëüêî îäèí ðàç
                if (!exifWritten) {
                    WriteApp1(writer, app1Length, exifPayload);
                    exifWritten = true;
                }
                continue;
            }
            // Îñòàëüíûå ñåãìåíòû êîïèðóåì êàê åñòü
            writer.Write((byte)0xFF);
            writer.Write(marker);
            WriteBigEndianUInt16(writer, length);
            writer.Write(segmentData);
        }
        File.WriteAllBytes(outputPath, output.ToArray());
    }

    private static void WriteApp1(
        BinaryWriter writer,
        ushort length,
        byte[] payload) {
        writer.Write((byte)0xFF);
        writer.Write((byte)0xE1);

        WriteBigEndianUInt16(writer, length);
        writer.Write(payload);
    }
    private static ushort ReadBigEndianUInt16(BinaryReader reader) {
        byte high = reader.ReadByte();
        byte low = reader.ReadByte();
        return (ushort)((high << 8) | low);
    }
    private static void WriteBigEndianUInt16(BinaryWriter writer, ushort value) {
        writer.Write((byte)(value >> 8));
        writer.Write((byte)(value & 0xFF));
    }
    public static void WriteStrategie(byte[] data, string path,AppSegment app1) {
        var file = File.ReadAllBytes(path);
        int currentOffset = 0;
        MemoryStream stream = new MemoryStream(file);
        BinaryReader reader = new BinaryReader(new MemoryStream(data));
        for (int i = 0; i < file.Length-5; i++) {
            ReadOnlySpan<byte> marker = file.AsSpan(i, 5);
            string forCompare = Encoding.UTF8.GetString(marker);
            if(forCompare == "Exif\0") {

            }
            byte b = reader.ReadByte();
            if (b == 0xFF) {

            }
        }
    }
}

