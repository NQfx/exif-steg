namespace Steganography.Shared;

public static partial class FileAnalysis 
{
    public static ExifGraph GetExifGraph(byte[] data)
    {
        if (data.Length < 8) throw new InvalidOperationException();

        var reader = new BytesReader(data);
        var graph = new ExifGraph();
        var map = new List<ExifBlock>();

        reader.Seek(0);
        bool isLittleEndian = data[0] == 0x49 && data[1] == 0x49;
        reader.IsLittleEndian = isLittleEndian;
        graph.IsLittleEndian = isLittleEndian;
        
        var header = new TiffHeaderNode { Id = 0 }; 
        graph.AddNode(header);
        map.Add(new ExifBlock { Offset = 0, Length = 8, Type = ExifBlockType.TiffHeader });

        reader.Seek(4);
        uint firstIfdOffset = reader.ReadUInt32();

        var offsetsToParse = new Queue<uint>();
        if (firstIfdOffset > 0) 
            offsetsToParse.Enqueue(firstIfdOffset);

        while (offsetsToParse.Count > 0)
        {
            uint offset = offsetsToParse.Dequeue();
            if (offset <= 0 || offset >= data.Length || map.Any(b => b.Offset == offset))
                continue;

            reader.Seek((int)offset);
            ushort count = reader.ReadUInt16();
            
            var currentIfd = new IfdNode { Id = offset };
            map.Add(new ExifBlock { Offset = (int)offset, Length = 2 + count * 12 + 4, Type = ExifBlockType.Ifd });

            for (int i = 0; i < count; i++)
            {
                reader.Seek((int)offset + 2 + (i * 12));
                var entry = new EntryNode
                {
                    Tag = reader.ReadUInt16(),
                    Type = reader.ReadUInt16(),
                    Count = reader.ReadUInt32()
                };
                
                uint valOrOff = reader.ReadUInt32();
                int dataSize = CalculateSize(entry.Type, entry.Count);

                if (dataSize > 4) // Ошибочная проверка, пропускает некоторые теги с ссылками на IFD + дублирование кода, пока костыль
                {
                    if (!map.Any(b => b.Offset == valOrOff))
                    {
                        map.Add(new ExifBlock { Offset = (int)valOrOff, Length = dataSize, Type = ExifBlockType.Data });
                        if (entry.Tag == 0x8769 || entry.Tag == 0x8825)
                        {
                            offsetsToParse.Enqueue(valOrOff);
                        }
                    }
                    entry.InlineData = BitConverter.GetBytes(valOrOff); 
                }
                else
                {
                    entry.InlineData = BitConverter.GetBytes(valOrOff);
                    if (entry.Tag == 0x8769 || entry.Tag == 0x8825)
                    {
                        offsetsToParse.Enqueue(valOrOff);
                    }
                }
                
                currentIfd.Entries.Add(entry);
            }

            uint nextIfd = reader.ReadUInt32();
            if (nextIfd > 0) 
            offsetsToParse.Enqueue(nextIfd);

            graph.AddNode(currentIfd);
        }

        long cursor = 0;
        var sortedBlocks = map.OrderBy(b => b.Offset).ToList();
        foreach (var b in sortedBlocks)
        {
            if (b.Offset > cursor && b.Type == ExifBlockType.Data)
            {
                var gapData = data[(int)cursor..(int)b.Offset];
                graph.AddNode(new DataNode { Id = cursor, Data = gapData});
            }
            cursor = b.Offset + b.Length;
        }

        foreach (var node in graph.Nodes)
        {
            if (node is IfdNode ifd)
            {
                foreach (var entry in ifd.Entries)
                {
                    int dataSize = CalculateSize(entry.Type, entry.Count);
                    if (dataSize > 4)
                    {
                        uint off = BitConverter.ToUInt32(entry.InlineData, 0);
                        entry.Pointer.Target = graph.Nodes.FirstOrDefault(n => n.Id == off);
                    }
                    else if (entry.Tag == 0x8769 || entry.Tag == 0x8825)
                    {
                        uint off = BitConverter.ToUInt32(entry.InlineData, 0);
                        entry.Pointer.Target = graph.Nodes.FirstOrDefault(n => n.Id == off);
                    }
                }
            }
        }

        return graph;
    }

    private static int CalculateSize(ushort type, uint count)
    {
        int[] typeSizes = { 0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8 };
        return (int)(count * (type < typeSizes.Length ? typeSizes[type] : 1));
    }

}
