using Steganography.Shared;

namespace Steganography.Tests;

public class UnitTest1
{
    [Fact]
    public void GetFileFormatTest()
    {
        var img1 = GetPath("img/1.jpg");
        var img2 = GetPath("img/2.png");
        var img3 = GetPath("img/3.gif");
        Assert.Equal(FileFormat.Jpeg, FileAnalysis.GetFileFormat(img1));
        Assert.Equal(FileFormat.Png, FileAnalysis.GetFileFormat(img2));
        Assert.Equal(FileFormat.Unknown, FileAnalysis.GetFileFormat(img3));
    }

    [Fact]
    public void GetJpegAppSegments()
    {
        var img = GetPath("img/bridge3.jpg");
        var segments = FileAnalysis.GetJpegAppSegments(img);

        foreach(var s in segments)
        {
            Console.WriteLine("APP" + s.AppNumber +" : "+ GetStringFromBytes(s.Identifier));
        }
        var app1 = new AppSegment();
                if (segments.Count > 0)
                    app1 = segments.Where(s  => System.Text.Encoding.UTF8.GetString(s.Identifier) == "Exif\0").First();
        Console.WriteLine(app1.Length);
        Console.WriteLine(GetStringFromBytes(app1.Data));
        // Assert.Equal(0, segments[0].AppNumber);
        // Assert.Equal(1, segments[1].AppNumber);
        // Assert.Equal("JFIF\0", GetStringFromBytes(segments[0].Identifier));
        // Assert.Equal("Exif\0", GetStringFromBytes(segments[1].Identifier));
    }

    [Fact]
    public void GetExifGraph()
    {
        var img = GetPath("img/bridge.jpg");
        var segments = FileAnalysis.GetJpegAppSegments(img);

        var graph = FileAnalysis.GetExifGraph(segments[0].Data);
        Console.WriteLine(graph.Nodes.Count);
        var ifd0 = graph.Nodes[2] as IfdNode;
        foreach(var i in graph.Nodes)
        {
            Console.WriteLine(i);
        }
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
                        if (data is null)
                            Console.WriteLine($"\t0x{i.Tag:X} {i.InlineData[0]}");
                        else
                            Console.WriteLine($"\t0x{i.Tag:X} {GetStringFromBytes(data.Data)}");

                    }
                }
            }
            else if (data is null)
                Console.WriteLine($"0x{e.Tag:X} {e.InlineData[0]}");
            else
                Console.WriteLine($"0x{e.Tag:X} {GetStringFromBytes(data.Data)}");
        }
    }

    private static string GetPath(string localPath) => "../../../" + localPath;
    private static string GetStringFromBytes(byte[] bytes) => System.Text.Encoding.UTF8.GetString(bytes);
}
