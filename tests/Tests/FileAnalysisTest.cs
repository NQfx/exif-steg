using System.ComponentModel;
using Steganography.Shared;

namespace Steganography.Tests;

public class UnitTest1
{
    [Fact]
    public void GetFileFormatTest()
    {
        var img1 = GetPath("img/cat.jpg");
        var img2 = GetPath("img/basketball.png");
        Assert.Equal(FileFormat.Jpeg, FileAnalysis.GetFileFormat(img1));
        Assert.Equal(FileFormat.Png, FileAnalysis.GetFileFormat(img2));
    }

    [Fact]
    public void GetJpegAppSegments()
    {
        var img = GetPath("img/cat.jpg");
        var segments = FileAnalysis.GetJpegAppSegments(img);

        foreach(var s in segments)
        {
            Console.WriteLine("APP" + s.AppNumber +" : "+ GetStringFromBytes(s.Identifier));
        }

        var app1 = segments.Where(s  => System.Text.Encoding.UTF8.GetString(s.Identifier) == "Exif\0\0").First();
        Assert.NotNull(app1);

        // Assert.Equal(0, segments[0].AppNumber);
        // Assert.Equal(1, segments[1].AppNumber);
        // Assert.Equal("JFIF\0", GetStringFromBytes(segments[0].Identifier));
        // Assert.Equal("Exif\0", GetStringFromBytes(segments[1].Identifier));
    }

    [Fact]
    public void GetExifGraphFromJpegTest()
    {
        var img = GetPath("img/cat.jpg");
        var segments = FileAnalysis.GetJpegAppSegments(img);
        
        var app1 = segments.Where(s  => System.Text.Encoding.UTF8.GetString(s.Identifier) == "Exif\0\0").FirstOrDefault();

        var graph = ExifAnalysis.GetExifGraph(app1.Data);
        app1.Data = graph.Compile();

        FileEdit.OverwriteJpegAppSegements(segments, img);

        segments = FileAnalysis.GetJpegAppSegments(img);
        app1 = segments.Where(s  => System.Text.Encoding.UTF8.GetString(s.Identifier) == "Exif\0\0").FirstOrDefault();

        graph = ExifAnalysis.GetExifGraph(app1.Data);

        var ifd0 = graph.Nodes.OfType<IfdNode>().First() as IfdNode;
        Assert.NotNull(ifd0);

        foreach(EntryNode e in ifd0.Entries)
        {
            var data = e.Pointer.Target as DataNode;
            if (e.Tag == 0x8769)
            {
                var target = e.Pointer.Target is IfdNode ? e.Pointer.Target as IfdNode : null;
                Console.WriteLine($"0x{e.Tag:X} IFD {target}");
                if (target != null)
                {
                    foreach(var i in target.Entries)
                    {
                        var data1 = i.Pointer.Target as DataNode;
                        if (data1 is null)
                            Console.WriteLine($"\t0x{i.Tag:X} {i.InlineData[0]}");
                        else
                            Console.WriteLine($"\t0x{i.Tag:X} {GetStringFromBytes(data1.Data)}");

                    }
                }
            }
            else if (data is null)
                Console.WriteLine($"0x{e.Tag:X} {e.InlineData[0]}");
            else
                Console.WriteLine($"0x{e.Tag:X} {GetStringFromBytes(data.Data)}");
        }
    }

    [Fact]
    public void GetPngChunksTest()
    {
        var img = GetPath("img/basketball.png");
        var chunks = FileAnalysis.GetPngChunks(img);

        Assert.True(chunks.Count >= 3);
        Assert.True(chunks.Where(e => {return e.Type != null && (GetStringFromBytes(e.Type) == "IHDR");}).Count() == 1);
        Assert.True(chunks.Where(e => {return e.Type != null && (GetStringFromBytes(e.Type) == "IEND");}).Count() == 1);
    }

    [Fact]
    public void GetExifGraphFromPngTest()
    {
        var img = GetPath("img/basketball.png");
        var chunks = FileAnalysis.GetPngChunks(img);
        var exifChunk = chunks.Where(e => {return e.Type != null && (GetStringFromBytes(e.Type) == "eXIf");}).First();
        var graph = ExifAnalysis.GetExifGraph(exifChunk.Data);
        var ifd0 = graph.Nodes.OfType<IfdNode>().First() as IfdNode;
        Assert.NotNull(ifd0);

        foreach(EntryNode e in ifd0.Entries)
        {
            var data = e.Pointer.Target as DataNode;
            if (e.Tag == 0x8769)
            {
                var target = e.Pointer.Target is IfdNode ? e.Pointer.Target as IfdNode : null;
                Console.WriteLine($"0x{e.Tag:X} IFD {target}");
                if (target != null)
                {
                    foreach(var i in target.Entries)
                    {
                        var data1 = i.Pointer.Target as DataNode;
                        if (data1 is null)
                            Console.WriteLine($"\t0x{i.Tag:X} {i.InlineData[0]}");
                        else
                            Console.WriteLine($"\t0x{i.Tag:X} {GetStringFromBytes(data1.Data)}");

                    }
                }
            }
            else if (data is null)
                Console.WriteLine($"0x{e.Tag:X} {e.InlineData[0]}");
            else
                Console.WriteLine($"0x{e.Tag:X} {GetStringFromBytes(data.Data)}");
        }
    }

    [Fact]
    public void OverwritePngChunksTest()
    {
        var img = GetPath("img/basketball.png");
        var oldChunks = FileAnalysis.GetPngChunks(img);
        FileEdit.OverwritePngChunks(oldChunks, img);
        var newChunks = FileAnalysis.GetPngChunks(img);
        for (int i = 0; i < oldChunks.Count; i++)
        {
            Assert.Equal(oldChunks[i].Crc, newChunks[i].Crc);
            Assert.Equal(oldChunks[i].Type, newChunks[i].Type);
            Assert.Equal(oldChunks[i].Data, newChunks[i].Data);
            Assert.Equal(oldChunks[i].Length, newChunks[i].Length);
        }
    }

    [Fact]
    public void MakerNotesStrategyTest()
    {
        var img = GetPath("img/basketball.png");

        var chunks = FileAnalysis.GetPngChunks(img);
        var exifChunk = chunks.Where(e => {return e.Type != null && (GetStringFromBytes(e.Type) == "eXIf");}).First();
        var graph = ExifAnalysis.GetExifGraph(exifChunk.Data);

        var text = new byte[]{116, 101, 120, 116};
        Strategies.AddMakerNotesEntry(graph, text);

        exifChunk.Data = graph.Compile();
        FileEdit.OverwritePngChunks(chunks, img);

        chunks = FileAnalysis.GetPngChunks(img);
        exifChunk = chunks.Find(e => {return e.Type != null && (GetStringFromBytes(e.Type) == "eXIf");});
        graph = ExifAnalysis.GetExifGraph(exifChunk.Data);

        var ifd0 = graph.Nodes.OfType<IfdNode>().First() as IfdNode;
        Assert.NotNull(ifd0);

        foreach(EntryNode e in ifd0.Entries)
        {
            var data = e.Pointer.Target as DataNode;
            if (e.Tag == 0x8769)
            {
                var target = e.Pointer.Target is IfdNode ? e.Pointer.Target as IfdNode : null;
                Console.WriteLine($"0x{e.Tag:X} IFD {target}");
                if (target != null)
                {
                    foreach(var i in target.Entries)
                    {
                        var data1 = i.Pointer.Target as DataNode;
                        if (data1 is null) 
                            Console.WriteLine($"\t0x{i.Tag:X} {GetStringFromBytes(e.InlineData)}");
                        else
                            Console.WriteLine($"\t0x{i.Tag:X} {GetStringFromBytes(data1.Data)}");

                    }
                }
            }
            else if (data is null)
                Console.WriteLine($"0x{e.Tag:X} {GetStringFromBytes(e.InlineData)}");
            else
                Console.WriteLine($"0x{e.Tag:X} {GetStringFromBytes(data.Data)}");
        }
    }


    private static string GetPath(string localPath) => "../../../" + localPath;
    private static string GetStringFromBytes(byte[] bytes) => System.Text.Encoding.UTF8.GetString(bytes);
}
