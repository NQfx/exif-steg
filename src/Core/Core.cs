using Steganography.Shared;
using System.Text;

namespace Steganography.Core;

public class CoreObject 
{
    public FileFormat Format { get; private set;}
    public string? FilePath { get; private set; }
    private Dictionary<int, ExifNode> dataBlocksIdTable = new();

    public AppSegment? App1Segment { get; private set; }

    public bool TrySelectFile(string path)
    {
        if (!File.Exists(path)) return false;
        Format = FileAnalysis.GetFileFormat(path);
        return true;
    }

    public List<DataBlock> GetDataBlocks()
    {
        var blocks = new List<DataBlock>();
        
        return blocks;
    }

    public string Read(bool isNeedReload) {
        LoadApp1();
        if (App1Segment.Data != null) return Encoding.UTF8.GetString(App1Segment.Data);
        else return string.Empty;

    }

   private void LoadApp1() {
        var segments = FileAnalysis.GetJpegAppSegments(Path);
        App1Segment = new AppSegment();
        App1Segment = segments.Where(s => System.Text.Encoding.UTF8.GetString(s.Identifier) == "Exif\0\0").FirstOrDefault();
        
    }
    public void DeleteOurApp1() {
        Shared.Strategies.WriteStrategieLegacy(Encoding.UTF8.GetBytes(""), Path, true);
    }
    public void Write(string text) {
        Shared.Strategies.WriteStrategieLegacy(Encoding.UTF8.GetBytes(text), Path);
    }

}